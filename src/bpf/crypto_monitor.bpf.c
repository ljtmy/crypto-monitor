#include "vmlinux.h"

#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../common.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 target_tgid = 0;
const volatile __u32 target_tid = 0;

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 32768);
  __type(key, __u32);
  __type(value, __u64);
} wakeup_ts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 32768);
  __type(key, __u32);
  __type(value, __u64);
} running_ts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 32768);
  __type(key, __u32);
  __type(value, __u64);
} crypto_start_ts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u8);
} tracked_tids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct thread_metrics);
} metrics SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, HIST_SLOTS);
  __type(key, __u32);
  __type(value, __u64);
} sched_latency_hist SEC(".maps");

static __always_inline bool match_target(__u32 tgid, __u32 tid) {
  if (target_tgid && target_tgid != tgid) {
    return false;
  }

  if (target_tid && target_tid != tid) {
    return false;
  }

  return true;
}

static __always_inline bool match_sched_target(__u32 tid) {
  __u8 *tracked;

  if (target_tid) {
    return target_tid == tid;
  }

  if (!target_tgid) {
    return true;
  }

  tracked = bpf_map_lookup_elem(&tracked_tids, &tid);
  return tracked != NULL;
}

static __always_inline struct thread_metrics *get_or_init_metrics(__u32 tid) {
  struct thread_metrics zero = {};
  struct thread_metrics *value;

  value = bpf_map_lookup_elem(&metrics, &tid);
  if (value) {
    return value;
  }

  bpf_map_update_elem(&metrics, &tid, &zero, BPF_ANY);
  return bpf_map_lookup_elem(&metrics, &tid);
}

static __always_inline void bump_histogram(__u64 delta_ns) {
  __u32 slot = 0;
  __u64 *count;
  __u64 v;

  if (delta_ns > 0) {
    /* Compute floor(log2(delta_ns)) using a loop instead of __builtin_clzll
     * to avoid an LLVM BPF backend crash in DAG instruction selection. */
    v = delta_ns;
    #pragma unroll
    for (int i = 0; i < 63; i++) {
      v >>= 1;
      if (v == 0)
        break;
      slot++;
    }
    if (slot >= HIST_SLOTS) {
      slot = HIST_SLOTS - 1;
    }
  }

  count = bpf_map_lookup_elem(&sched_latency_hist, &slot);
  if (count) {
    *count += 1;
  }
}

static __always_inline int handle_sched_wakeup_event(__u32 pid) {
  __u64 ts;

  if (!match_sched_target(pid)) {
    return 0;
  }

  ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
  return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx) {
  return handle_sched_wakeup_event(ctx->pid);
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx) {
  return handle_sched_wakeup_event(ctx->pid);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
  __u64 now = bpf_ktime_get_ns();
  __u32 prev_pid = ctx->prev_pid;
  __u32 next_pid = ctx->next_pid;
  __u64 *running_start;
  __u64 *wake_start;
  struct thread_metrics *prev_metrics;
  struct thread_metrics *next_metrics;
  __u64 delta;

  if (match_sched_target(prev_pid)) {
    prev_metrics = get_or_init_metrics(prev_pid);
    if (prev_metrics) {
      prev_metrics->context_switches++;
      if (ctx->prev_state == 0) {
        prev_metrics->involuntary_switches++;
      } else {
        prev_metrics->voluntary_switches++;
      }
      bpf_get_current_comm(prev_metrics->comm, sizeof(prev_metrics->comm));
    }

    running_start = bpf_map_lookup_elem(&running_ts, &prev_pid);
    if (running_start && prev_metrics && now > *running_start) {
      prev_metrics->cpu_time_ns += now - *running_start;
    }
    bpf_map_delete_elem(&running_ts, &prev_pid);
  }

  if (match_sched_target(next_pid)) {
    next_metrics = get_or_init_metrics(next_pid);
    if (next_metrics) {
      bpf_probe_read_kernel_str(next_metrics->comm, sizeof(next_metrics->comm),
                                ctx->next_comm);
    }

    bpf_map_update_elem(&running_ts, &next_pid, &now, BPF_ANY);
    wake_start = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
    if (wake_start && next_metrics && now > *wake_start) {
      delta = now - *wake_start;
      next_metrics->sched_latency_samples++;
      next_metrics->sched_latency_total_ns += delta;
      if (delta > next_metrics->sched_latency_max_ns) {
        next_metrics->sched_latency_max_ns = delta;
      }
      bump_histogram(delta);
      bpf_map_delete_elem(&wakeup_ts, &next_pid);
    }
  }

  return 0;
}

SEC("uprobe/crypto_enter")
int BPF_KPROBE(handle_crypto_enter) {
  __u64 id = bpf_get_current_pid_tgid();
  __u32 tgid = id >> 32;
  __u32 tid = (__u32)id;
  __u64 now = bpf_ktime_get_ns();
  struct thread_metrics *metric;
  __u8 tracked = 1;

  if (!match_target(tgid, tid)) {
    return 0;
  }

  metric = get_or_init_metrics(tid);
  if (!metric) {
    return 0;
  }

  metric->crypto_calls++;
  bpf_get_current_comm(metric->comm, sizeof(metric->comm));
  bpf_map_update_elem(&tracked_tids, &tid, &tracked, BPF_ANY);
  bpf_map_update_elem(&crypto_start_ts, &tid, &now, BPF_ANY);
  return 0;
}

SEC("uretprobe/crypto_exit")
int BPF_KRETPROBE(handle_crypto_exit, int ret) {
  __u64 id = bpf_get_current_pid_tgid();
  __u32 tgid = id >> 32;
  __u32 tid = (__u32)id;
  __u64 now = bpf_ktime_get_ns();
  __u64 *start_ts;
  struct thread_metrics *metric;

  if (!match_target(tgid, tid)) {
    return 0;
  }

  metric = get_or_init_metrics(tid);
  if (!metric) {
    return 0;
  }

  if (ret < 0) {
    metric->crypto_errors++;
  }

  start_ts = bpf_map_lookup_elem(&crypto_start_ts, &tid);
  if (start_ts && now > *start_ts) {
    metric->crypto_time_ns += now - *start_ts;
    bpf_map_delete_elem(&crypto_start_ts, &tid);
  }

  return 0;
}
