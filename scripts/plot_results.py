#!/usr/bin/env python3
"""Plot crypto-monitor experiment results."""

import json
import re
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = "/home/ubuntu/repos/crypto-monitor/results"
PLOTS_DIR = "/home/ubuntu/repos/crypto-monitor/results/plots"
os.makedirs(PLOTS_DIR, exist_ok=True)

THREAD_COUNTS = [1, 4, 8, 16]

# ── Parse monitor JSON results ──────────────────────────────────────────
monitor_data = {}
for t in THREAD_COUNTS:
    path = os.path.join(RESULTS_DIR, f"monitor-{t}.json")
    with open(path) as f:
        monitor_data[t] = json.load(f)

# ── Parse openssl speed throughput ──────────────────────────────────────
throughput = {}
for t in THREAD_COUNTS:
    path = os.path.join(RESULTS_DIR, f"openssl-speed-{t}.log")
    with open(path) as f:
        content = f.read()
    f_lines = re.findall(
        r'\+F:21:aes-256-cbc:([\d.]+):([\d.]+):([\d.]+):([\d.]+):([\d.]+):([\d.]+)',
        content)
    # Sum throughput across all workers for 16384-byte blocks (last column)
    throughput[t] = sum(float(m[5]) for m in f_lines) / 1e6  # MB/s

# ── Derived metrics ─────────────────────────────────────────────────────
duration_s = 15
ctx_switches_per_s = {t: d["context_switches"] / duration_s for t, d in monitor_data.items()}
cpu_pct = {t: d["cpu_time_ns"] / (duration_s * 1e9) * 100 for t, d in monitor_data.items()}
avg_sched_us = {}
p95_sched_us = {}
max_sched_us = {}

for t, d in monitor_data.items():
    samples = d["sched_latency_samples"]
    if samples > 0:
        avg_sched_us[t] = d["sched_latency_total_ns"] / samples / 1000
    else:
        avg_sched_us[t] = 0
    max_sched_us[t] = d["sched_latency_max_ns"] / 1000

    # Compute p95 from histogram
    hist = d["sched_latency_histogram"]
    total = sum(s["count"] for s in hist)
    target = int(total * 0.95)
    cumulative = 0
    p95_slot = 0
    for s in hist:
        cumulative += s["count"]
        if cumulative >= target:
            p95_slot = s["slot"]
            break
    p95_sched_us[t] = (2 ** p95_slot) / 1000  # ns -> us

crypto_calls = {t: d["crypto_calls"] for t, d in monitor_data.items()}

x = np.array(THREAD_COUNTS)

# ── Plot style ──────────────────────────────────────────────────────────
plt.rcParams.update({
    'figure.figsize': (10, 6),
    'font.size': 12,
    'axes.grid': True,
    'grid.alpha': 0.3,
})
colors = ['#2196F3', '#FF5722', '#4CAF50', '#9C27B0']

# ── 1. Thread Count vs Throughput ───────────────────────────────────────
fig, ax = plt.subplots()
tp = [throughput[t] for t in THREAD_COUNTS]
ax.plot(x, tp, 'o-', color=colors[0], linewidth=2, markersize=8)
ax.set_xlabel('Thread Count')
ax.set_ylabel('Throughput (MB/s)')
ax.set_title('OpenSSL AES-256-CBC Throughput vs Thread Count')
ax.set_xticks(THREAD_COUNTS)
fig.tight_layout()
fig.savefig(os.path.join(PLOTS_DIR, '1_throughput_vs_threads.png'), dpi=150)
plt.close()

# ── 2. Thread Count vs Context Switches/s ──────────────────────────────
fig, ax = plt.subplots()
cs = [ctx_switches_per_s[t] for t in THREAD_COUNTS]
ax.bar(x, cs, width=1.5, color=colors[1], alpha=0.8, edgecolor='black')
ax.set_xlabel('Thread Count')
ax.set_ylabel('Context Switches / s')
ax.set_title('Context Switches per Second vs Thread Count')
ax.set_xticks(THREAD_COUNTS)
fig.tight_layout()
fig.savefig(os.path.join(PLOTS_DIR, '2_context_switches_vs_threads.png'), dpi=150)
plt.close()

# ── 3. Thread Count vs Scheduling Latency (avg + p95 + max) ────────────
fig, ax = plt.subplots()
avg = [avg_sched_us[t] for t in THREAD_COUNTS]
p95 = [p95_sched_us[t] for t in THREAD_COUNTS]
mx = [max_sched_us[t] for t in THREAD_COUNTS]
ax.plot(x, avg, 'o-', color=colors[0], linewidth=2, markersize=8, label='Avg')
ax.plot(x, p95, 's--', color=colors[1], linewidth=2, markersize=8, label='P95')
ax.plot(x, mx, '^:', color=colors[3], linewidth=2, markersize=8, label='Max')
ax.set_xlabel('Thread Count')
ax.set_ylabel('Scheduling Latency (us)')
ax.set_title('Scheduling Latency vs Thread Count')
ax.set_xticks(THREAD_COUNTS)
ax.legend()
fig.tight_layout()
fig.savefig(os.path.join(PLOTS_DIR, '3_sched_latency_vs_threads.png'), dpi=150)
plt.close()

# ── 4. Thread Count vs CPU Time % ──────────────────────────────────────
fig, ax = plt.subplots()
cpu = [cpu_pct[t] for t in THREAD_COUNTS]
ax.bar(x, cpu, width=1.5, color=colors[2], alpha=0.8, edgecolor='black')
ax.set_xlabel('Thread Count')
ax.set_ylabel('CPU Time (%)')
ax.set_title('CPU Utilization vs Thread Count')
ax.set_xticks(THREAD_COUNTS)
ax.axhline(y=200, color='red', linestyle='--', alpha=0.5, label='2 CPUs = 200%')
ax.legend()
fig.tight_layout()
fig.savefig(os.path.join(PLOTS_DIR, '4_cpu_time_vs_threads.png'), dpi=150)
plt.close()

# ── 5. Context Switches/s vs Throughput ─────────────────────────────────
fig, ax = plt.subplots()
for i, t in enumerate(THREAD_COUNTS):
    ax.scatter(ctx_switches_per_s[t], throughput[t], s=100, zorder=5,
               color=colors[i % len(colors)])
    ax.annotate(f'{t} threads', (ctx_switches_per_s[t], throughput[t]),
                textcoords="offset points", xytext=(10, 5), fontsize=10)
ax.set_xlabel('Context Switches / s')
ax.set_ylabel('Throughput (MB/s)')
ax.set_title('Context Switches vs Throughput')
fig.tight_layout()
fig.savefig(os.path.join(PLOTS_DIR, '5_ctx_switches_vs_throughput.png'), dpi=150)
plt.close()

# ── 6. Combined dashboard ──────────────────────────────────────────────
fig, axes = plt.subplots(2, 2, figsize=(14, 10))

ax = axes[0, 0]
ax.plot(x, tp, 'o-', color=colors[0], linewidth=2, markersize=8)
ax.set_xlabel('Thread Count')
ax.set_ylabel('Throughput (MB/s)')
ax.set_title('Throughput')
ax.set_xticks(THREAD_COUNTS)
ax.grid(True, alpha=0.3)

ax = axes[0, 1]
ax.bar(x, cs, width=1.5, color=colors[1], alpha=0.8, edgecolor='black')
ax.set_xlabel('Thread Count')
ax.set_ylabel('Context Switches / s')
ax.set_title('Context Switches')
ax.set_xticks(THREAD_COUNTS)
ax.grid(True, alpha=0.3)

ax = axes[1, 0]
ax.plot(x, avg, 'o-', color=colors[0], linewidth=2, markersize=8, label='Avg')
ax.plot(x, p95, 's--', color=colors[1], linewidth=2, markersize=8, label='P95')
ax.plot(x, mx, '^:', color=colors[3], linewidth=2, markersize=8, label='Max')
ax.set_xlabel('Thread Count')
ax.set_ylabel('Latency (us)')
ax.set_title('Scheduling Latency')
ax.set_xticks(THREAD_COUNTS)
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)

ax = axes[1, 1]
ax.bar(x, cpu, width=1.5, color=colors[2], alpha=0.8, edgecolor='black')
ax.set_xlabel('Thread Count')
ax.set_ylabel('CPU Time (%)')
ax.set_title('CPU Utilization')
ax.set_xticks(THREAD_COUNTS)
ax.axhline(y=200, color='red', linestyle='--', alpha=0.5, label='2 CPUs')
ax.legend(fontsize=9)
ax.grid(True, alpha=0.3)

fig.suptitle('crypto-monitor: OpenSSL AES-256-CBC Performance Analysis', fontsize=14, fontweight='bold')
fig.tight_layout()
fig.savefig(os.path.join(PLOTS_DIR, '6_dashboard.png'), dpi=150)
plt.close()

# ── 7. Scheduling Latency Histogram ────────────────────────────────────
fig, ax = plt.subplots(figsize=(12, 6))
width = 0.2
offsets = np.arange(len(THREAD_COUNTS))
for i, t in enumerate(THREAD_COUNTS):
    hist = monitor_data[t]["sched_latency_histogram"]
    slots = [s["slot"] for s in hist if s["count"] > 0]
    counts = [s["count"] for s in hist if s["count"] > 0]
    if slots:
        labels = [f"2^{s}" for s in slots]
        positions = np.arange(len(slots))
        ax.bar(positions + i * width, counts, width=width, label=f'{t} threads',
               color=colors[i], alpha=0.8, edgecolor='black', linewidth=0.5)
        if i == 0:
            ax.set_xticks(positions + width * (len(THREAD_COUNTS) - 1) / 2)
            ax.set_xticklabels(labels, rotation=45, fontsize=9)
ax.set_xlabel('Latency Bucket (ns, log2 scale)')
ax.set_ylabel('Sample Count')
ax.set_title('Scheduling Latency Histogram Distribution')
ax.legend()
fig.tight_layout()
fig.savefig(os.path.join(PLOTS_DIR, '7_latency_histogram.png'), dpi=150)
plt.close()

print("All plots saved to:", PLOTS_DIR)
print("Files:", os.listdir(PLOTS_DIR))
