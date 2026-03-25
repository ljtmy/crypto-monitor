#ifndef CRYPTO_MONITOR_COMMON_H
#define CRYPTO_MONITOR_COMMON_H

#ifndef __VMLINUX_H__
#include <linux/types.h> //不加条件判断会冲突
#endif

#define TASK_COMM_LEN 16  //进程名长度
#define HIST_SLOTS 64     //对数直方图槽位数量

enum monitor_event_type {
  MONITOR_EVENT_NONE = 0,
  MONITOR_EVENT_SNAPSHOT = 1,
  MONITOR_EVENT_CRYPTO = 2,
};
//将用户态的过滤规则打包,传递给内核态进行过滤
struct monitor_filter {
  __u32 target_tgid;
  __u32 target_tid;
};
// 线程指标结构体，记录各种统计数据
struct thread_metrics {
  __u64 cpu_time_ns;            // 线程实际占用 CPU 运行的累积时间
  __u64 context_switches;       // 线程发生的总上下文切换次数
  __u64 voluntary_switches;     // 自愿上下文切换次数
  __u64 involuntary_switches;   // 非自愿上下文切换次数
  __u64 sched_latency_samples;  // 线程被唤醒后等待 CPU 的次数
  __u64 sched_latency_total_ns; // 线程等待 CPU 的总延迟时间
  __u64 sched_latency_max_ns;   // 线程遇到过的单次最大等待 CPU 延迟
  __u64 crypto_calls;           // 调用应用层加密函数的总次数
  __u64 crypto_errors;          // 加密函数返回错误的次数
  __u64 crypto_time_ns;         // 执行应用层加密函数的累积耗时
  char comm[TASK_COMM_LEN];     // 线程的名称（长度为16）
};
// 对数直方图桶结构体
struct histogram_bucket {
  __u64 slot; // 桶位索引
  __u64 count;  // 落在该桶位的样本数量
};

#endif

