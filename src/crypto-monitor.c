#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "crypto_monitor.skel.h"

static volatile sig_atomic_t exiting;

struct cli_options {
  pid_t pid;
  pid_t tid;
  int interval_sec;
  int duration_sec;
  const char *binary_path;
  const char *symbol;
  const char *output_path;
  const char *output_format;
};

struct aggregate_snapshot {
  __u64 cpu_time_ns;
  __u64 context_switches;
  __u64 voluntary_switches;
  __u64 involuntary_switches;
  __u64 sched_latency_samples;
  __u64 sched_latency_total_ns;
  __u64 sched_latency_max_ns;
  __u64 crypto_calls;
  __u64 crypto_errors;
  __u64 crypto_time_ns;
  __u64 histogram[HIST_SLOTS];
};

static void sig_handler(int signo) {
  (void)signo;
  exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]\n"
          "  --pid PID              target process id\n"
          "  --tid TID              target thread id\n"
          "  --binary PATH          binary or shared library for uprobe\n"
          "  --symbol NAME          symbol to trace, default EVP_CipherUpdate\n"
          "  --interval SEC         screen refresh interval, default 2\n"
          "  --duration SEC         total run time, default 0 means until Ctrl-C\n"
          "  --output PATH          export result path\n"
          "  --format json|csv      export format, default json\n",
          prog);
}

static int parse_args(int argc, char **argv, struct cli_options *opts) {
  static const struct option long_options[] = {
      {"pid", required_argument, NULL, 'p'},
      {"tid", required_argument, NULL, 't'},
      {"binary", required_argument, NULL, 'b'},
      {"symbol", required_argument, NULL, 's'},
      {"interval", required_argument, NULL, 'i'},
      {"duration", required_argument, NULL, 'd'},
      {"output", required_argument, NULL, 'o'},
      {"format", required_argument, NULL, 'f'},
      {"help", no_argument, NULL, 'h'},
      {}};
  int opt;

  opts->interval_sec = 2;
  opts->duration_sec = 0;
  opts->symbol = "EVP_CipherUpdate";
  opts->output_format = "json";

  while ((opt = getopt_long(argc, argv, "p:t:b:s:i:d:o:f:h", long_options,
                            NULL)) != -1) {
    switch (opt) {
      case 'p':
        opts->pid = (pid_t)atoi(optarg);
        break;
      case 't':
        opts->tid = (pid_t)atoi(optarg);
        break;
      case 'b':
        opts->binary_path = optarg;
        break;
      case 's':
        opts->symbol = optarg;
        break;
      case 'i':
        opts->interval_sec = atoi(optarg);
        break;
      case 'd':
        opts->duration_sec = atoi(optarg);
        break;
      case 'o':
        opts->output_path = optarg;
        break;
      case 'f':
        opts->output_format = optarg;
        break;
      case 'h':
      default:
        usage(argv[0]);
        return -1;
    }
  }

  if (!opts->binary_path) {
    fprintf(stderr, "--binary is required\n");
    return -1;
  }

  if (opts->interval_sec <= 0) {
    fprintf(stderr, "--interval must be > 0\n");
    return -1;
  }

  if (strcmp(opts->output_format, "json") != 0 &&
      strcmp(opts->output_format, "csv") != 0) {
    fprintf(stderr, "--format must be json or csv\n");
    return -1;
  }

  return 0;
}

static int bump_memlock_rlimit(void) {
  struct rlimit rlim = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int read_histogram(int map_fd, __u64 histogram[HIST_SLOTS]) {
  __u32 key;

  memset(histogram, 0, sizeof(__u64) * HIST_SLOTS);
  for (key = 0; key < HIST_SLOTS; key++) {
    if (bpf_map_lookup_elem(map_fd, &key, &histogram[key]) != 0) {
      return -errno;
    }
  }

  return 0;
}

static int read_metrics_map(int map_fd, struct aggregate_snapshot *snap) {
  __u32 key;
  __u32 next_key;
  struct thread_metrics metric;
  int err;
  bool has_key = false;

  memset(snap, 0, sizeof(*snap));
  while ((err = bpf_map_get_next_key(map_fd, has_key ? &key : NULL,
                                     &next_key)) == 0) {
    if (bpf_map_lookup_elem(map_fd, &next_key, &metric) == 0) {
      snap->cpu_time_ns += metric.cpu_time_ns;
      snap->context_switches += metric.context_switches;
      snap->voluntary_switches += metric.voluntary_switches;
      snap->involuntary_switches += metric.involuntary_switches;
      snap->sched_latency_samples += metric.sched_latency_samples;
      snap->sched_latency_total_ns += metric.sched_latency_total_ns;
      if (metric.sched_latency_max_ns > snap->sched_latency_max_ns) {
        snap->sched_latency_max_ns = metric.sched_latency_max_ns;
      }
      snap->crypto_calls += metric.crypto_calls;
      snap->crypto_errors += metric.crypto_errors;
      snap->crypto_time_ns += metric.crypto_time_ns;
    }
    key = next_key;
    has_key = true;
  }

  if (err && errno != ENOENT) {
    return -errno;
  }

  return 0;
}

static double percentile_from_histogram(const __u64 hist[HIST_SLOTS],
                                        double percentile) {
  __u64 total = 0;
  __u64 cumulative = 0;
  __u32 i;
  __u64 target;

  for (i = 0; i < HIST_SLOTS; i++) {
    total += hist[i];
  }

  if (total == 0) {
    return 0.0;
  }

  target = (__u64)((percentile / 100.0) * (double)total);
  if (target == 0) {
    target = 1;
  }

  for (i = 0; i < HIST_SLOTS; i++) {
    cumulative += hist[i];
    if (cumulative >= target) {
      return (double)(1ULL << i) / 1000.0;
    }
  }

  return (double)(1ULL << (HIST_SLOTS - 1)) / 1000.0;
}

static void print_snapshot(const struct aggregate_snapshot *curr,
                           const struct aggregate_snapshot *prev,
                           int interval_sec) {
  __u64 delta_crypto = curr->crypto_calls - prev->crypto_calls;
  __u64 delta_switches = curr->context_switches - prev->context_switches;
  __u64 delta_cpu = curr->cpu_time_ns - prev->cpu_time_ns;
  __u64 delta_sched_samples =
      curr->sched_latency_samples - prev->sched_latency_samples;
  __u64 delta_sched_total_ns =
      curr->sched_latency_total_ns - prev->sched_latency_total_ns;
  double cpu_util = 0.0;
  double avg_sched_us = 0.0;
  char timebuf[64];
  time_t now = time(NULL);
  struct tm tm_now;

  localtime_r(&now, &tm_now);
  strftime(timebuf, sizeof(timebuf), "%F %T", &tm_now);

  if (interval_sec > 0) {
    cpu_util = (double)delta_cpu / (interval_sec * 1000000000.0) * 100.0;
  }
  if (delta_sched_samples > 0) {
    avg_sched_us = (double)delta_sched_total_ns / delta_sched_samples / 1000.0;
  }

  printf("[%s] calls/s=%llu switches/s=%llu cpu=%.2f%% avg_sched=%.2fus "
         "p50=%.2fus p95=%.2fus max=%.2fus errors=%llu\n",
         timebuf, (unsigned long long)(delta_crypto / interval_sec),
         (unsigned long long)(delta_switches / interval_sec), cpu_util,
         avg_sched_us, percentile_from_histogram(curr->histogram, 50.0),
         percentile_from_histogram(curr->histogram, 95.0),
         (double)curr->sched_latency_max_ns / 1000.0,
         (unsigned long long)curr->crypto_errors);
}

static int write_json(const char *path, const struct aggregate_snapshot *snap) {
  FILE *fp = fopen(path, "w");
  size_t i;

  if (!fp) {
    return -errno;
  }

  fprintf(fp,
          "{\n"
          "  \"cpu_time_ns\": %llu,\n"
          "  \"context_switches\": %llu,\n"
          "  \"voluntary_switches\": %llu,\n"
          "  \"involuntary_switches\": %llu,\n"
          "  \"sched_latency_samples\": %llu,\n"
          "  \"sched_latency_total_ns\": %llu,\n"
          "  \"sched_latency_max_ns\": %llu,\n"
          "  \"crypto_calls\": %llu,\n"
          "  \"crypto_errors\": %llu,\n"
          "  \"crypto_time_ns\": %llu,\n"
          "  \"sched_latency_histogram\": [\n",
          (unsigned long long)snap->cpu_time_ns,
          (unsigned long long)snap->context_switches,
          (unsigned long long)snap->voluntary_switches,
          (unsigned long long)snap->involuntary_switches,
          (unsigned long long)snap->sched_latency_samples,
          (unsigned long long)snap->sched_latency_total_ns,
          (unsigned long long)snap->sched_latency_max_ns,
          (unsigned long long)snap->crypto_calls,
          (unsigned long long)snap->crypto_errors,
          (unsigned long long)snap->crypto_time_ns);

  for (i = 0; i < HIST_SLOTS; i++) {
    fprintf(fp, "    {\"slot\": %zu, \"count\": %llu}%s\n", i,
            (unsigned long long)snap->histogram[i],
            (i + 1 == HIST_SLOTS) ? "" : ",");
  }

  fprintf(fp, "  ]\n}\n");
  fclose(fp);
  return 0;
}

static int write_csv(const char *path, const struct aggregate_snapshot *snap) {
  FILE *fp = fopen(path, "w");
  size_t i;

  if (!fp) {
    return -errno;
  }

  fprintf(fp,
          "cpu_time_ns,context_switches,voluntary_switches,"
          "involuntary_switches,sched_latency_samples,sched_latency_total_ns,"
          "sched_latency_max_ns,crypto_calls,crypto_errors,crypto_time_ns\n");
  fprintf(fp, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
          (unsigned long long)snap->cpu_time_ns,
          (unsigned long long)snap->context_switches,
          (unsigned long long)snap->voluntary_switches,
          (unsigned long long)snap->involuntary_switches,
          (unsigned long long)snap->sched_latency_samples,
          (unsigned long long)snap->sched_latency_total_ns,
          (unsigned long long)snap->sched_latency_max_ns,
          (unsigned long long)snap->crypto_calls,
          (unsigned long long)snap->crypto_errors,
          (unsigned long long)snap->crypto_time_ns);
  fprintf(fp, "\nslot,count\n");
  for (i = 0; i < HIST_SLOTS; i++) {
    fprintf(fp, "%zu,%llu\n", i, (unsigned long long)snap->histogram[i]);
  }

  fclose(fp);
  return 0;
}

static int export_snapshot(const struct cli_options *opts,
                           const struct aggregate_snapshot *snap) {
  if (!opts->output_path) {
    return 0;
  }

  if (strcmp(opts->output_format, "csv") == 0) {
    return write_csv(opts->output_path, snap);
  }

  return write_json(opts->output_path, snap);
}

static int attach_uprobes(struct crypto_monitor_bpf *skel,
                          const struct cli_options *opts) {
  LIBBPF_OPTS(bpf_uprobe_opts, enter_opts, .func_name = opts->symbol);
  LIBBPF_OPTS(bpf_uprobe_opts, exit_opts, .func_name = opts->symbol,
              .retprobe = true);

  skel->links.handle_crypto_enter =
      bpf_program__attach_uprobe_opts(skel->progs.handle_crypto_enter,
                                      opts->pid ? opts->pid : -1,
                                      opts->binary_path, 0, &enter_opts);
  if (libbpf_get_error(skel->links.handle_crypto_enter)) {
    return (int)-libbpf_get_error(skel->links.handle_crypto_enter);
  }

  skel->links.handle_crypto_exit =
      bpf_program__attach_uprobe_opts(skel->progs.handle_crypto_exit,
                                      opts->pid ? opts->pid : -1,
                                      opts->binary_path, 0, &exit_opts);
  if (libbpf_get_error(skel->links.handle_crypto_exit)) {
    return (int)-libbpf_get_error(skel->links.handle_crypto_exit);
  }

  return 0;
}

int main(int argc, char **argv) {
  struct crypto_monitor_bpf *skel = NULL;
  struct cli_options opts = {};
  struct aggregate_snapshot curr = {};
  struct aggregate_snapshot prev = {};
  int metrics_fd;
  int hist_fd;
  int err;
  int elapsed = 0;

  libbpf_set_print(libbpf_print_fn);

  if (parse_args(argc, argv, &opts) != 0) {
    return 1;
  }

  if (bump_memlock_rlimit() != 0) {
    perror("setrlimit");
    return 1;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = crypto_monitor_bpf__open();
  if (!skel) {
    fprintf(stderr, "failed to open skeleton\n");
    return 1;
  }

  skel->rodata->target_tgid = opts.pid > 0 ? (__u32)opts.pid : 0;
  skel->rodata->target_tid = opts.tid > 0 ? (__u32)opts.tid : 0;

  err = crypto_monitor_bpf__load(skel);
  if (err) {
    fprintf(stderr, "failed to load skeleton: %d\n", err);
    goto cleanup;
  }

  err = crypto_monitor_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "failed to attach tracepoints: %d\n", err);
    goto cleanup;
  }

  err = attach_uprobes(skel, &opts);
  if (err) {
    fprintf(stderr, "failed to attach uprobes: %d\n", err);
    goto cleanup;
  }

  metrics_fd = bpf_map__fd(skel->maps.metrics);
  hist_fd = bpf_map__fd(skel->maps.sched_latency_hist);

  printf("Tracing pid=%d tid=%d symbol=%s from %s every %ds\n",
         opts.pid ? opts.pid : -1, opts.tid ? opts.tid : -1, opts.symbol,
         opts.binary_path, opts.interval_sec);

  while (!exiting) {
    sleep(opts.interval_sec);
    elapsed += opts.interval_sec;

    err = read_metrics_map(metrics_fd, &curr);
    if (err) {
      fprintf(stderr, "failed to read metrics map: %d\n", err);
      goto cleanup;
    }

    err = read_histogram(hist_fd, curr.histogram);
    if (err) {
      fprintf(stderr, "failed to read histogram: %d\n", err);
      goto cleanup;
    }

    print_snapshot(&curr, &prev, opts.interval_sec);
    prev = curr;

    if (opts.duration_sec > 0 && elapsed >= opts.duration_sec) {
      break;
    }
  }

  err = export_snapshot(&opts, &curr);
  if (err) {
    fprintf(stderr, "failed to export result: %d\n", err);
    goto cleanup;
  }

cleanup:
  crypto_monitor_bpf__destroy(skel);
  return err != 0;
}
