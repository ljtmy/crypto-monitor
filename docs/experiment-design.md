# 基于 eBPF 的系统性能监测与分析实验设计文档

## 1. 目标与交付

本实验面向“模拟密码运算负载下的系统性能监测与分析”场景，交付以下内容：

- `crypto-monitor` 命令行工具
- 基于 `openssl speed` 的模拟负载实验方案
- 面向 1、4、8、16、64、128 线程的实验脚本
- 监测点选择依据、指标口径、结果记录模板与分析方法

用户态程序采用 `libbpf skeleton` 框架，便于后续迁移到真实 PCIe 密码设备
场景，并保持内核态/用户态接口清晰稳定。

## 2. 研究重点与方案映射

### 2.1 多维度性能指标的 eBPF 探测方法

监测点设计如下：

- `tracepoint:sched/sched_wakeup`
  记录线程被唤醒的时间戳，作为调度延迟起点
- `tracepoint:sched/sched_wakeup_new`
  处理新建线程第一次被唤醒的情况
- `tracepoint:sched/sched_switch`
  统计上下文切换次数，并在目标线程切入 CPU 时计算
  `scheduling latency = switch_in_ts - wakeup_ts`
- `uprobe/uretprobe`
  绑定 OpenSSL 指定符号，统计调用频率、错误次数和累计耗时

这样可以形成从“用户态加密函数调用”到“线程调度行为”的关联链路：

1. `openssl speed` 在用户态触发加密函数
2. eBPF uprobe 记录加密调用次数和持续时间
3. 调度 tracepoint 记录该负载对应线程的 wakeup/switch 行为
4. 用户态定时聚合 map，建立吞吐量与调度开销的关联分析

### 2.2 eBPF Map 数据聚合策略与开销控制

为满足高并发和高频采样的低开销目标，采用以下策略：

- `LRU_HASH(wakeup_ts)`：记录线程唤醒时间戳，自动淘汰冷数据
- `LRU_HASH(running_ts)`：记录线程最近一次切入 CPU 的时间戳
- `LRU_HASH(crypto_start_ts)`：记录加密函数入口时间，便于返回时统计耗时
- `LRU_HASH(metrics)`：以 `tid` 为键聚合线程级指标
- `ARRAY(sched_latency_hist)`：记录对数桶延迟分布，避免高频 ring buffer 上报

开销控制原则：

- 内核态只做计数、累加、直方图分桶，不做字符串格式化和大量事件上报
- 实时展示采用“用户态周期拉取 map”的方式，避免每个事件都发往用户态
- 调度延迟采用对数桶统计，既保留分布特征，又控制 map 写入成本
- 使用 `target pid/tid` 过滤，减少无关任务带来的探测开销

### 2.3 模拟加密工作负载下的性能建模与分析

负载模型选用 `openssl speed`：

- 原因 1：标准化程度高，便于重复实验和横向对比
- 原因 2：支持多线程参数 `-multi`
- 原因 3：可选择对称算法或哈希算法，便于模拟不同计算特征

推荐主实验算法：

- `aes-256-cbc`

可选补充算法：

- `sha256`
- `aes-128-gcm`
- `rsa2048`

性能关联模型如下：

`线程数增加 -> 竞争增强 -> wakeup 次数与切换频率上升 -> scheduling latency 增大 -> 单线程有效 CPU 时间下降 -> 总吞吐量出现边际递减`

## 3. 工具实现说明

### 3.0 总体逻辑架构图

```text
+---------------------------+        +-------------------------------+
| openssl speed -multi N    |        | crypto-monitor CLI           |
| aes-256-cbc / sha256 ...  |        | libbpf skeleton              |
+-------------+-------------+        +---------------+---------------+
              |                                              ^
              | user-space crypto call                       |
              v                                              |
+---------------------------+                                |
| uprobe / uretprobe        |--------------------------------+
| EVP_CipherUpdate ...      |   read maps / periodic report / export
+-------------+-------------+
              |
              v
+---------------------------+        +-------------------------------+
| eBPF maps                 |<-------| tracepoint:sched_wakeup       |
| tracked_tids              |        | tracepoint:sched_wakeup_new   |
| wakeup_ts                 |        | tracepoint:sched_switch       |
| running_ts                |        +-------------------------------+
| crypto_start_ts           |
| metrics(tid -> counters)  |
| sched_latency_hist        |
+---------------------------+
```

### 3.1 用户态程序

用户态程序使用 skeleton 框架：

- `crypto_monitor_bpf__open()`
- `crypto_monitor_bpf__load()`
- `crypto_monitor_bpf__attach()`

其中：

- tracepoint 通过 skeleton 自动附着
- OpenSSL 符号通过 `bpf_program__attach_uprobe_opts()` 动态绑定

CLI 支持：

- 指定 `--pid` 或 `--tid`
- 指定 `--binary` 和 `--symbol`
- 周期输出实时统计
- 导出 `JSON/CSV`

### 3.2 指标定义

- `crypto_calls`
  目标加密符号调用次数
- `crypto_time_ns`
  目标加密符号累计执行时间
- `context_switches`
  目标线程被切出的总次数
- `voluntary_switches`
  主动让出 CPU 的切换次数
- `involuntary_switches`
  被抢占导致的切换次数
- `sched_latency_samples`
  记录到的调度延迟样本数
- `sched_latency_total_ns`
  调度延迟总和，用于计算平均值
- `sched_latency_histogram`
  延迟分布直方图，用于计算 p50/p95
- `cpu_time_ns`
  线程在 CPU 上运行的累计时间

### 3.3 低开销设计说明

为了满足“1 万次/秒事件频率下额外 CPU 占用低于单核 5%”的考核目标，
本实现优先保证以下性质：

- 内核态按线程聚合，不向用户态逐事件打印
- 采用静态 map 布局，避免复杂动态内存操作
- 使用 `LRU_HASH` 控制高并发线程下 map 膨胀
- 直方图使用 `ARRAY`，仅更新计数器

## 4. 实验环境建议

建议实验环境如下：

- Linux 内核：5.15 及以上
- CPU：8 核及以上
- 内存：16 GB 及以上
- OpenSSL：3.x
- 编译工具链：`clang + bpftool + libbpf`

实验时需要关闭明显干扰项：

- 避免同时运行高负载后台任务
- 固定 CPU 频率策略，减少动态调频扰动
- 尽量在空闲系统上重复 3 次以上取平均

## 5. 实验步骤

### 5.1 构建工具

```bash
make
```

### 5.2 启动单组实验

先启动负载：

```bash
openssl speed -multi 16 -seconds 30 aes-256-cbc
```

查询 `openssl` 进程 PID 后启动监控：

```bash
sudo ./build/crypto-monitor \
  --pid <PID> \
  --binary /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
  --symbol EVP_CipherUpdate \
  --duration 30 \
  --output result-16.json \
  --format json
```

### 5.3 批量实验

线程组：

- 1
- 4
- 8
- 16
- 64
- 128

脚本执行：

```bash
./scripts/run_experiment.sh /usr/lib/x86_64-linux-gnu/libcrypto.so.3 EVP_CipherUpdate
```

输出文件：

- `results/openssl-speed-<threads>.log`
- `results/monitor-<threads>.log`
- `results/monitor-<threads>.json`

## 6. 数据记录模板

建议整理为如下表格：

| 线程数 | OpenSSL 吞吐量 MB/s | crypto_calls/s | context_switches/s | avg sched latency(us) | p95 sched latency(us) | CPU 利用率(%) |
|---|---:|---:|---:|---:|---:|---:|
| 1 |  |  |  |  |  |  |
| 4 |  |  |  |  |  |  |
| 8 |  |  |  |  |  |  |
| 16 |  |  |  |  |  |  |
| 64 |  |  |  |  |  |  |
| 128 |  |  |  |  |  |  |

## 7. 考核指标验证方法

### 7.1 监测准确性

与系统工具对比：

- `perf stat -p <pid> -e context-switches,cpu-clock`
- `pidstat -wt -p <pid> 1`
- `top -H -p <pid>`

判定方式：

- `crypto-monitor` 的 CPU 利用率、线程切换频率与对标工具偏差控制在 ±5%

### 7.2 系统开销

方法：

1. 不启用监控，执行 `openssl speed`
2. 启用 `crypto-monitor`，执行同样参数
3. 比较两组场景的 CPU 使用率、吞吐量和总耗时

判定建议：

- 单核额外 CPU 占用低于 5%
- 对吞吐量影响不超过 5%

### 7.3 并发处理能力

在 `-multi 128` 场景下检查：

- 是否稳定输出实时数据
- map 是否出现明显读写失败
- 调度延迟直方图是否持续增长
- `crypto_calls` 是否与负载时长和吞吐量变化趋势一致

## 8. 结果分析建议

重点画出以下曲线：

- 线程数 vs OpenSSL 吞吐量
- 线程数 vs `context_switches/s`
- 线程数 vs `avg sched latency`
- 线程数 vs `p95 sched latency`
- `context_switches/s` vs 吞吐量

建议关注的现象：

- 低线程阶段，吞吐量随线程数近似线性提升
- 中高线程阶段，切换频率快速上升
- 当 `p95 scheduling latency` 明显抬升后，吞吐量增益趋缓
- 若 CPU 时间持续增加但吞吐量未同步增长，说明竞争开销开始主导

## 9. 迁移到 PCIe 密码设备的建议

当前实现主要覆盖“应用线程调度 + 用户态加密调用”链路。后续迁移到真实
PCIe 密码设备时，可继续扩展：

- 对设备驱动 ioctl、提交队列函数增加 `kprobe/fentry`
- 对 DMA 提交、完成中断、软中断处理增加 tracepoint 观测
- 建立“应用请求 -> 驱动排队 -> 设备完成”的端到端延迟链路
- 在保留当前线程调度指标的同时，叠加设备队列深度和硬件完成延迟

## 10. 当前实现边界

本项目已经满足课程设计/课题原型所需的核心交付结构，但在真实部署前需要
注意以下边界：

- `openssl speed` 实际命中的 OpenSSL 符号可能因版本和算法不同而变化
- 不同发行版的 `libcrypto.so` 路径不同，需要通过 `ldd $(which openssl)` 确认
- 由于当前仓库环境不是 Linux eBPF 运行环境，需在目标 Linux 主机完成构建和实测
