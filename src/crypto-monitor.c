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
// 这是 bpftool 自动生成的 C 骨架头文件，包含了内核态 eBPF 程序的结构定义和生命周期函数
#include "crypto_monitor.skel.h"

// 全局退出标志位，用于捕捉 Ctrl+C (SIGINT) 信号实现优雅退出，防止 eBPF 探针残留
static volatile sig_atomic_t exiting;

// 命令行参数配置结构体
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

// 用户态聚合快照：用于将内核 BPF Map 中分散在各个线程的数据汇总到一起
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
  __u64 histogram[HIST_SLOTS]; // 调度延迟直方图数组
};

// 信号处理函数：安全地将退出标志位置为 1，让主循环自然结束
static void sig_handler(int signo) {
  (void)signo;
  exiting = 1;
}

// libbpf 自定义打印回调：用于过滤掉 libbpf 底层繁杂的 DEBUG 日志，保持终端清爽
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

// 打印帮助文档
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

// 标准的 C 语言 getopt_long 命令行参数解析逻辑
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

  // 设置默认值
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

  // 参数校验
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

// 【极其重要】解除内核内存锁定限制
// BPF Map 需要在内核中常驻物理内存。Linux 默认严格限制普通进程锁定的内存量，
// 如果不调用此函数解除限制，bpf_object__load 会因为无法分配 Map 内存而直接报错。
static int bump_memlock_rlimit(void) {
  struct rlimit rlim = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

// 【Map 交互】从内核的 Array Map 中读取直方图数据
static int read_histogram(int map_fd, __u64 histogram[HIST_SLOTS]) {
  __u32 key;

  memset(histogram, 0, sizeof(__u64) * HIST_SLOTS);
  // Array Map 的 Key 就是连续的整数索引 (0 到 HIST_SLOTS-1)
  // 直接通过循环调用 bpf_map_lookup_elem 查表即可把整个数组拷贝到用户态
  for (key = 0; key < HIST_SLOTS; key++) {
    if (bpf_map_lookup_elem(map_fd, &key, &histogram[key]) != 0) {
      return -errno;
    }
  }

  return 0;
}

// 【经典范式】遍历 BPF Hash Map 并进行全局数据聚合
static int read_metrics_map(int map_fd, struct aggregate_snapshot *snap) {
  __u32 key;
  __u32 next_key;
  struct thread_metrics metric;
  int err;
  bool has_key = false;

  memset(snap, 0, sizeof(*snap));
  
  // 因为 Hash Map 的 Key (TID) 是离散未知的，必须使用 bpf_map_get_next_key 进行迭代
  // 传入当前 key，内核返回下一个 next_key，直到遍历完整个 Map
  while ((err = bpf_map_get_next_key(map_fd, has_key ? &key : NULL,
                                     &next_key)) == 0) {
    // 拿到 next_key 后，去 Map 里把对应的 metric 结构体取出来
    if (bpf_map_lookup_elem(map_fd, &next_key, &metric) == 0) {
      // 将单个线程的统计指标累加到全局的 snap 快照中
      snap->cpu_time_ns += metric.cpu_time_ns;
      snap->context_switches += metric.context_switches;
      snap->voluntary_switches += metric.voluntary_switches;
      snap->involuntary_switches += metric.involuntary_switches;
      snap->sched_latency_samples += metric.sched_latency_samples;
      snap->sched_latency_total_ns += metric.sched_latency_total_ns;
      
      // 维护系统全局的最大调度延迟
      if (metric.sched_latency_max_ns > snap->sched_latency_max_ns) {
        snap->sched_latency_max_ns = metric.sched_latency_max_ns;
      }
      snap->crypto_calls += metric.crypto_calls;
      snap->crypto_errors += metric.crypto_errors;
      snap->crypto_time_ns += metric.crypto_time_ns;
    }
    // 更新 key 准备下一次迭代
    key = next_key;
    has_key = true;
  }

  // 遍历到 Map 末尾时，内核会返回 ENOENT (No such file or directory)
  // 这是正常结束的标志，不是真正的错误
  if (err && errno != ENOENT) {
    return -errno;
  }

  return 0;
}

// 纯数学逻辑：根据直方图桶 (Slots) 的分布情况，估算指定的百分位数 (如 P50, P95)
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

// 打印两个时间快照之间的增量 (Delta) 指标，计算出诸如每秒调用次数 (TPS) 等速率指标
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

// 文件 I/O：将最终的聚合数据导出为 JSON 格式
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

// 文件 I/O：将最终的聚合数据导出为 CSV 格式
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

// 导出功能路由函数
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

// 解析 ELF 共享库中指定符号的偏移地址，用于 uprobe 挂载
static long resolve_symbol_offset(const char *binary_path, const char *symbol) {
  char cmd[512];
  char line[256];
  FILE *fp;
  long offset = -1;

  /* Use grep with word boundary before symbol and allow optional version
   * suffix like @@OPENSSL_3.0.0 after the symbol name. */
  snprintf(cmd, sizeof(cmd),
           "nm -D '%s' 2>/dev/null | grep -E ' T %s(@@|$)'",
           binary_path, symbol);
  fp = popen(cmd, "r");
  if (!fp) {
    return -1;
  }
  if (fgets(line, sizeof(line), fp)) {
    offset = strtol(line, NULL, 16);
  }
  pclose(fp);
  return offset;
}

// 【高级应用】动态挂载用户态探针 (Uprobe)
// 完美解决了 "Uprobe 不能在 eBPF 源码里写死绝对路径" 的工程难题
static int attach_uprobes(struct crypto_monitor_bpf *skel,
                          const struct cli_options *opts) {
  long sym_offset;

  /* Attach uprobe system-wide (pid=-1) so that child processes forked by
   * 'openssl speed -multi N' are also traced.  The BPF-side target_tgid
   * filter ensures only events from the target process group are recorded. */

  sym_offset = resolve_symbol_offset(opts->binary_path, opts->symbol);
  if (sym_offset < 0) {
    fprintf(stderr, "failed to resolve symbol '%s' in '%s'\n",
            opts->symbol, opts->binary_path);
    return -1;
  }

  // 挂载入口探针 (uprobe)
  skel->links.handle_crypto_enter =
      bpf_program__attach_uprobe(skel->progs.handle_crypto_enter,
                                 false, -1,
                                 opts->binary_path, (size_t)sym_offset);
  if (libbpf_get_error(skel->links.handle_crypto_enter)) {
    return (int)-libbpf_get_error(skel->links.handle_crypto_enter);
  }

  // 挂载出口探针 (uretprobe)
  skel->links.handle_crypto_exit =
      bpf_program__attach_uprobe(skel->progs.handle_crypto_exit,
                                 true, -1,
                                 opts->binary_path, (size_t)sym_offset);
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

  // 设置 libbpf 日志回调
  libbpf_set_print(libbpf_print_fn);

  // 1. 解析命令行并解除内存锁定限制
  if (parse_args(argc, argv, &opts) != 0) {
    return 1;
  }

  if (bump_memlock_rlimit() != 0) {
    perror("setrlimit");
    return 1;
  }

  // 注册信号处理，捕获 Ctrl-C 以便优雅清理资源
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  // 2. Open 阶段：打开 BPF 对象，分配内存结构，但暂时不将指令加载进内核
  skel = crypto_monitor_bpf__open();
  if (!skel) {
    fprintf(stderr, "failed to open skeleton\n");
    return 1;
  }

  // 【核心技巧】通过修改只读数据段 (rodata) 注入全局过滤配置
  // 在内核 eBPF 代码中定义了诸如 'const volatile __u32 target_tgid;'
  // 在 load 进内核之前，我们在用户态将命令行传入的 PID/TID 填进去。
  // 这样 eBPF 虚拟机在 JIT 编译时会把它当成常量，实现零性能损耗的精准过滤。
  skel->rodata->target_tgid = opts.pid > 0 ? (__u32)opts.pid : 0;
  skel->rodata->target_tid = opts.tid > 0 ? (__u32)opts.tid : 0;

  // 3. Load 阶段：将 BPF 字节码发送给内核验证器(Verifier)进行安全校验，并分配真实的 Map 内存
  err = crypto_monitor_bpf__load(skel);
  if (err) {
    fprintf(stderr, "failed to load skeleton: %d\n", err);
    goto cleanup;
  }

  // 4. Attach 阶段：激活内核态探针 (如 Tracepoint, Kprobe)
  // 注意：这个 API 只会自动挂载那些 SEC 声明完全符合规范且无需动态路径的探针
  err = crypto_monitor_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "failed to attach tracepoints: %d\n", err);
    goto cleanup;
  }

  // 手动挂载 Uprobe，传入用户态解析好的动态参数
  err = attach_uprobes(skel, &opts);
  if (err) {
    fprintf(stderr, "failed to attach uprobes: %d\n", err);
    goto cleanup;
  }

  // 获取 BPF Map 在当前进程中的文件描述符 (FD)
  // 后续所有的读写操作（如 bpf_map_lookup_elem）都要依赖这两个 FD
  metrics_fd = bpf_map__fd(skel->maps.metrics);
  hist_fd = bpf_map__fd(skel->maps.sched_latency_hist);

  printf("Tracing pid=%d tid=%d symbol=%s from %s every %ds\n",
         opts.pid ? opts.pid : -1, opts.tid ? opts.tid : -1, opts.symbol,
         opts.binary_path, opts.interval_sec);

  // 5. 数据处理主循环：以指定的时间间隔定期拉取数据
  while (!exiting) {
    sleep(opts.interval_sec);
    elapsed += opts.interval_sec;

    // 从内核抽取最新的 Metrics 指标和直方图状态
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

    // 打印本次时间窗口内的增量报表
    print_snapshot(&curr, &prev, opts.interval_sec);
    // 更新旧快照，为下一次循环做准备
    prev = curr;

    if (opts.duration_sec > 0 && elapsed >= opts.duration_sec) {
      break;
    }
  }

  // 退出循环时，将收集到的聚合数据导出到文件
  err = export_snapshot(&opts, &curr);
  if (err) {
    fprintf(stderr, "failed to export result: %d\n", err);
    goto cleanup;
  }

cleanup:
  // 6. Destroy 阶段：卸载并销毁 BPF 程序，归还内核内存资源
  // 即便程序意外终止，只要走到这里，系统就不会留下脏数据
  crypto_monitor_bpf__destroy(skel);
  return err != 0;
}
