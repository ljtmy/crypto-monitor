#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../common.h"

char LICENSE[] SEC("license") = "Dual/GPL";//许可证

// 全局过滤配置，由用户态加载器在挂载 eBPF 程序前动态写入
// 如果保持为 0，则代表不进行过滤
const volatile __u32 target_tgid = 0; // 目标进程组 ID 
const volatile __u32 target_tid = 0;  // 目标线程 ID

// 记录线程被唤醒 (加入运行队列) 的时间戳
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 32768);
  __type(key, __u32); // TID
  __type(value, __u64); // 纳秒时间戳
} wakeup_ts SEC(".maps");

// 记录线程真正拿到 CPU 开始运行的时间戳 (用于计算 CPU 实际占用时间)
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 32768);
  __type(key, __u32);
  __type(value, __u64);
} running_ts SEC(".maps");

// 记录用户态触发加密函数 (crypto_enter) 的时间戳
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 32768);
  __type(key, __u32);
  __type(value, __u64);
} crypto_start_ts SEC(".maps");

// 黑名单/白名单过滤：记录哪些线程真正调用过加密函数。
// 作用：内核调度器 tracepoint 是全系统触发的，开销极大。
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u8); // value 无实际意义，仅作为 Set 使用
} tracked_tids SEC(".maps");

// 核心统计指标数据表，每个 TID 对应一份统计指标
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct thread_metrics); 
} metrics SEC(".maps");

// 调度延迟的对数直方图 (使用 ARRAY 提高读取性能)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, HIST_SLOTS); 
  __type(key, __u32);
  __type(value, __u64);
} sched_latency_hist SEC(".maps");



 //辅助函数 (Helper Functions)

// 严格匹配：检查当前 TGID 和 TID 是否匹配用户配置的目标
static __always_inline bool match_target(__u32 tgid, __u32 tid) {
  if (target_tgid && target_tgid != tgid) {
    return false;
  }
  if (target_tid && target_tid != tid) {
    return false;
  }
  return true;
}

// 调度器事件匹配逻辑：决定是否需要追踪某个 TID 的调度状态
static __always_inline bool match_sched_target(__u32 tid) {
  __u8 *tracked;

  if (target_tid) {
    return target_tid == tid; // 精确匹配某个线程
  }
  if (!target_tgid) {
    return true; // 没有指定 TGID 时，监控全系统所有调度
  }

  // 如果指定了进程级 TGID，则只监控那些触发了 crypto_enter 被加入白名单的线程
  tracked = bpf_map_lookup_elem(&tracked_tids, &tid);
  return tracked != NULL;
}

// 获取或初始化指标结构体
static __always_inline struct thread_metrics *get_or_init_metrics(__u32 tid) {
  struct thread_metrics zero = {};
  struct thread_metrics *value; //声明一个指针用于接收从map中查到的地址

  value = bpf_map_lookup_elem(&metrics, &tid); //在metrics表中查找当前线程的指标结构体地址
  if (value) {
    return value;
  }//查到了就直接返回指针地址

  bpf_map_update_elem(&metrics, &tid, &zero, BPF_ANY); //没有查到就先插入一个全0的结构体占位
  return bpf_map_lookup_elem(&metrics, &tid);//返回这个新插入的结构体地址。
}

// 直方图插槽计算及累加
static __always_inline void bump_histogram(__u64 delta_ns) {
  __u32 slot = 0;
  __u64 *count;

  if (delta_ns > 0) {
    // 高级性能优化：使用 GCC 内建函数 __builtin_clzll (Count Leading Zeros)
    // 63 - 领头的0的个数，可以直接极其高效地计算出 log2(delta_ns) 所在的槽位，避免了 for 循环展开
    slot = 63 - __builtin_clzll(delta_ns);
    if (slot >= HIST_SLOTS) {
      slot = HIST_SLOTS - 1; // 防止越界
    }
  }

  count = bpf_map_lookup_elem(&sched_latency_hist, &slot);
  if (count) {
    // 由于是全局 ARRAY，多核可能会同时写同一个槽位，必须使用原子加保护
    __sync_fetch_and_add(count, 1);
  }
}

// 记录唤醒时间的通用处理逻辑
static __always_inline int handle_sched_wakeup_event(__u32 pid) {
  __u64 ts;

  if (!match_sched_target(pid)) {
    return 0;
  }

  ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
  return 0;
}


/*  探针定义：内核调度器追踪 (Tracepoints) */

// 探针：线程被唤醒，准备加入 CPU 运行队列（Runqueue）
SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx) {
  return handle_sched_wakeup_event(ctx->pid);
}

// 探针：新创建的线程首次被唤醒
SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup *ctx) {
  return handle_sched_wakeup_event(ctx->pid);
}

// 探针：CPU 上发生真正的线程上下文切换 (极其高频)
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
  __u64 now = bpf_ktime_get_ns();
  __u32 prev_pid = ctx->prev_pid; // 即将被踢下 CPU 的线程
  __u32 next_pid = ctx->next_pid; // 即将跑在 CPU 上的线程
  __u64 *running_start;
  __u64 *wake_start;
  struct thread_metrics *prev_metrics;
  struct thread_metrics *next_metrics;
  __u64 delta;

  // 1. 处理被踢下 CPU 的线程 (prev)
  if (match_sched_target(prev_pid)) {
    prev_metrics = get_or_init_metrics(prev_pid);
    if (prev_metrics) {
      prev_metrics->context_switches++; 
      // ctx->prev_state 为 0 (TASK_RUNNING) 说明它是被时间片耗尽或高优先级任务强行抢占的 -> 非自愿切换
      // 不为 0 说明它自己主动休眠了 (如等锁、I/O、usleep) -> 自愿切换
      if (ctx->prev_state == 0) 
      {
        prev_metrics->involuntary_switches++;
      } else {
        prev_metrics->voluntary_switches++;
      }
      bpf_get_current_comm(prev_metrics->comm, sizeof(prev_metrics->comm)); // 更新进程名
    }

    // 计算本次该线程在 CPU 上到底跑了多久 (实际 CPU 耗时)
    running_start = bpf_map_lookup_elem(&running_ts, &prev_pid);
    if (running_start && prev_metrics && now > *running_start) {
      prev_metrics->cpu_time_ns += now - *running_start;
    }
    bpf_map_delete_elem(&running_ts, &prev_pid); // 已经下 CPU 了，清除记录
  }

  // 2. 处理即将上 CPU 运行的线程 (next)
  if (match_sched_target(next_pid)) {
    next_metrics = get_or_init_metrics(next_pid);
    if (next_metrics) {
      // 从内核结构中安全读取进程名
      bpf_probe_read_kernel_str(next_metrics->comm, sizeof(next_metrics->comm),
                                ctx->next_comm);
    }

    // 记录拿到 CPU 开始运行的时间戳
    bpf_map_update_elem(&running_ts, &next_pid, &now, BPF_ANY);
    
    // 计算调度延迟 
    wake_start = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
    if (wake_start && next_metrics && now > *wake_start) {
      delta = now - *wake_start; 
      next_metrics->sched_latency_samples++;  // 统计被唤醒后成功调度的次数
      next_metrics->sched_latency_total_ns += delta;  // 累积调度延迟时间
      if (delta > next_metrics->sched_latency_max_ns) // 更新最大调度延迟
      {
        next_metrics->sched_latency_max_ns = delta;
      }
      bump_histogram(delta); // 计入直方图分布
      bpf_map_delete_elem(&wakeup_ts, &next_pid); // 清除唤醒记录，等待下一次循环
    }
  }

  return 0;
}


/*
 探针定义：应用层加密库追踪 (Uprobes)
 （利用 BPF_KPROBE 宏包装，其实际挂载点由用户态程序指定为 uprobe）*/

// 探针：进入加密函数
SEC("uprobe/crypto_enter")
int BPF_KPROBE(handle_crypto_enter) 
{
  __u64 id = bpf_get_current_pid_tgid();  
  __u32 tgid = id >> 32;  
  __u32 tid = (__u32)id;
  __u64 now = bpf_ktime_get_ns();
  struct thread_metrics *metric;
  __u8 tracked = 1; // 只要调用过加密函数一次，就把这个线程加入监控名单，不再区分它后续是否还调用加密函数了

  if (!match_target(tgid, tid)) //进行过滤
  {
    return 0;
  }

  metric = get_or_init_metrics(tid);//初始化
  if (!metric) 
  {
    return 0;
  }

  metric->crypto_calls++;//调用次数加1
  bpf_get_current_comm(metric->comm, sizeof(metric->comm));
  
  // 核心逻辑：一旦该线程碰了加密接口，就把它加入调度器监控名单，
  // 这样就能过滤掉同进程内其他无关的后台线程
  bpf_map_update_elem(&tracked_tids, &tid, &tracked, BPF_ANY);
  
  // 记录加密开始时间
  bpf_map_update_elem(&crypto_start_ts, &tid, &now, BPF_ANY);
  return 0;
}

// 探针：退出加密函数
SEC("uretprobe/crypto_exit")
int BPF_KRETPROBE(handle_crypto_exit, int ret) 
{
  __u64 id = bpf_get_current_pid_tgid();
  __u32 tgid = id >> 32;
  __u32 tid = (__u32)id;
  __u64 now = bpf_ktime_get_ns();
  __u64 *start_ts;
  struct thread_metrics *metric;

  if (!match_target(tgid, tid))
  {
    return 0;
  }

  metric = get_or_init_metrics(tid);
  if (!metric) 
  {
    return 0;
  }

  // 假设根据目标函数的规约，返回值 < 0 为失败状态
  if (ret < 0) 
  {
    metric->crypto_errors++;  //错误次数加1
  }

  // 计算此次加密调用的耗时
  start_ts = bpf_map_lookup_elem(&crypto_start_ts, &tid);
  if (start_ts && now > *start_ts) {
    metric->crypto_time_ns += now - *start_ts;
    bpf_map_delete_elem(&crypto_start_ts, &tid); // 算完即删，防止内存泄露
  }

  return 0;
}