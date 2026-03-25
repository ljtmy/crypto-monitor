# crypto-monitor

`crypto-monitor` 是一个基于 eBPF CO-RE + libbpf skeleton 的性能监测 CLI，
用于在 `openssl speed` 模拟加密负载下，采集线程上下文切换、调度延迟和
加密函数调用频率等指标。

## 功能

- 基于 `tracepoint:sched/sched_switch`、`sched_wakeup`、`sched_wakeup_new`
  统计线程切换频率与调度延迟分布
- 基于 `uprobe/uretprobe` 监测 OpenSSL 指定符号的调用次数与累计耗时
- 按周期输出实时统计信息
- 导出聚合结果为 `CSV` 或 `JSON`
- 面向 `openssl speed` 的实验脚本与实验设计文档

## 目录

- `src/bpf/crypto_monitor.bpf.c`：内核态 eBPF 程序
- `src/crypto-monitor.c`：基于 skeleton 的用户态 CLI
- `src/common.h`：共享结构体与常量
- `scripts/run_openssl_speed.sh`：单次 OpenSSL speed 负载脚本
- `scripts/run_experiment.sh`：多线程实验批处理脚本
- `docs/experiment-design.md`：完整实验设计与分析文档

## 构建环境

建议在 Linux 5.15+ 环境构建和运行，并安装：

- `clang`
- `llvm`
- `bpftool`
- `libbpf`
- `libelf`
- `zlib`
- `openssl`

Ubuntu/Debian 参考：

```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev openssl
```

## 构建

```bash
make
```

构建过程会自动：

1. 从 `/sys/kernel/btf/vmlinux` 生成 `src/bpf/vmlinux.h`
2. 编译 eBPF 对象文件
3. 生成 `crypto_monitor.skel.h`
4. 编译用户态 CLI

## 基本使用

监测 `openssl speed` 进程的 `EVP_CipherUpdate` 调用，并每 2 秒刷新一次：

```bash
sudo ./build/crypto-monitor \
  --pid <openssl-speed-pid> \
  --binary /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
  --symbol EVP_CipherUpdate \
  --interval 2
```

导出 JSON：

```bash
sudo ./build/crypto-monitor \
  --pid <openssl-speed-pid> \
  --binary /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
  --symbol EVP_CipherUpdate \
  --duration 30 \
  --output result.json \
  --format json
```

## OpenSSL speed 负载

单次运行示例：

```bash
./scripts/run_openssl_speed.sh 16 aes-256-cbc 30
```

批量实验示例：

```bash
./scripts/run_experiment.sh /usr/lib/x86_64-linux-gnu/libcrypto.so.3 EVP_CipherUpdate
```

## 文档

详细实验步骤、监测点选择依据、指标定义和迁移到 PCIe 密码设备的建议见
[`docs/experiment-design.md`](docs/experiment-design.md)。

