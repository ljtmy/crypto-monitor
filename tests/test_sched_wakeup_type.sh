#!/usr/bin/env bash
#
# Regression test for commit aa29bedb:
#   "函数参数对不上内核vmlinux的实际存在"
#   (Function parameters don't match the actual kernel vmlinux)
#
# The original bug used 'struct trace_event_raw_sched_wakeup' as the context
# parameter type for the sched_wakeup and sched_wakeup_new tracepoint handlers.
# However, the kernel's vmlinux BTF defines the type as
# 'struct trace_event_raw_sched_wakeup_template'. Using the wrong type causes
# a compilation error because the struct is not defined in vmlinux.h and its
# members (e.g. ->pid) cannot be accessed.
#
# This test:
#   1. Generates vmlinux.h from the running kernel's BTF
#   2. Verifies the correct type exists in vmlinux.h
#   3. Verifies the source code uses the correct type (not the old wrong one)
#   4. Compiles a minimal BPF program with the WRONG (old) type and confirms
#      it FAILS — reproducing the original bug
#   5. Compiles a minimal BPF program with the CORRECT (fixed) type and
#      confirms it SUCCEEDS — verifying the fix
#
# Prerequisites: clang, bpftool, libbpf-dev, /sys/kernel/btf/vmlinux
#

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BPF_SRC="${REPO_ROOT}/src/bpf/crypto_monitor.bpf.c"
VMLINUX_H="${REPO_ROOT}/src/bpf/vmlinux.h"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

echo "=== Regression test: sched_wakeup tracepoint parameter type (aa29bedb) ==="
echo ""

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
BPFTOOL=""
# Prefer the actual versioned binary over the wrapper at /usr/sbin/bpftool,
# which may emit warnings to stdout and break piped output.
for f in /usr/lib/linux-tools/*/bpftool; do
    if [ -x "$f" ]; then
        BPFTOOL="$f"
        break
    fi
done
if [ -z "$BPFTOOL" ]; then
    # Fall back to PATH / well-known location
    if command -v bpftool &>/dev/null; then
        BPFTOOL="bpftool"
    elif [ -x /usr/sbin/bpftool ]; then
        BPFTOOL="/usr/sbin/bpftool"
    fi
fi

if [ -z "$BPFTOOL" ]; then
    echo "ERROR: bpftool not found. Install linux-tools-generic or equivalent."
    exit 1
fi

if ! command -v clang &>/dev/null; then
    echo "ERROR: clang not found. Install clang."
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found. Kernel BTF required."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Generate vmlinux.h from kernel BTF
# ---------------------------------------------------------------------------
echo "--- Step 1: Generate vmlinux.h from kernel BTF ---"
GENERATED_VMLINUX="${TMPDIR}/vmlinux.h"
if $BPFTOOL btf dump file /sys/kernel/btf/vmlinux format c > "$GENERATED_VMLINUX" 2>/dev/null; then
    echo "  Generated vmlinux.h ($(wc -l < "$GENERATED_VMLINUX") lines)"
else
    echo "ERROR: Failed to generate vmlinux.h from kernel BTF"
    exit 1
fi
echo ""

# ---------------------------------------------------------------------------
# Step 2: Verify the correct type exists in vmlinux.h
# ---------------------------------------------------------------------------
echo "--- Step 2: Verify trace_event_raw_sched_wakeup_template exists in vmlinux.h ---"
if grep -q 'struct trace_event_raw_sched_wakeup_template {' "$GENERATED_VMLINUX"; then
    pass "trace_event_raw_sched_wakeup_template is defined in kernel vmlinux.h"
else
    fail "trace_event_raw_sched_wakeup_template NOT found in kernel vmlinux.h"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 3: Verify the source code uses the correct type
# ---------------------------------------------------------------------------
echo "--- Step 3: Verify source code uses the correct type ---"

# 3a: The fixed source should use trace_event_raw_sched_wakeup_template
CORRECT_COUNT=$(grep -c 'trace_event_raw_sched_wakeup_template' "$BPF_SRC" || true)
if [ "$CORRECT_COUNT" -ge 2 ]; then
    pass "Source uses trace_event_raw_sched_wakeup_template ($CORRECT_COUNT occurrences for wakeup + wakeup_new)"
else
    fail "Source should use trace_event_raw_sched_wakeup_template in both handlers (found $CORRECT_COUNT)"
fi

# 3b: The source should NOT use the old incorrect type (bare sched_wakeup without _template)
#     We need to match 'trace_event_raw_sched_wakeup' but NOT 'trace_event_raw_sched_wakeup_template'
WRONG_COUNT=$(grep -cP 'trace_event_raw_sched_wakeup\b(?!_template)' "$BPF_SRC" || true)
if [ "$WRONG_COUNT" -eq 0 ]; then
    pass "Source does not use the old incorrect type trace_event_raw_sched_wakeup"
else
    fail "Source still uses the old incorrect type trace_event_raw_sched_wakeup ($WRONG_COUNT occurrences)"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 4: Compile with WRONG type — should FAIL (reproduces the original bug)
# ---------------------------------------------------------------------------
echo "--- Step 4: Compile with WRONG type (reproduce original bug) ---"
cat > "${TMPDIR}/test_wrong_type.c" << 'BPFEOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* Original (buggy) code used trace_event_raw_sched_wakeup which does not
   exist in the kernel's vmlinux BTF. Accessing ctx->pid on an incomplete
   type must fail. */
SEC("tracepoint/sched/sched_wakeup")
int test_wakeup_wrong(struct trace_event_raw_sched_wakeup *ctx) {
    return ctx->pid;
}

SEC("tracepoint/sched/sched_wakeup_new")
int test_wakeup_new_wrong(struct trace_event_raw_sched_wakeup *ctx) {
    return ctx->pid;
}
BPFEOF

WRONG_OUTPUT=$(clang -O2 -target bpf -D__TARGET_ARCH_x86 \
    -I"${TMPDIR}" \
    -c "${TMPDIR}/test_wrong_type.c" \
    -o "${TMPDIR}/test_wrong_type.o" 2>&1 || true)
WRONG_EXIT=$?

if [ ! -f "${TMPDIR}/test_wrong_type.o" ] || [ $WRONG_EXIT -ne 0 ] || echo "$WRONG_OUTPUT" | grep -q 'error:'; then
    pass "Compilation with wrong type trace_event_raw_sched_wakeup correctly FAILED"
    echo "  (Error excerpt: $(echo "$WRONG_OUTPUT" | grep 'error:' | head -1))"
else
    fail "Compilation with wrong type trace_event_raw_sched_wakeup should have failed but succeeded"
fi
echo ""

# ---------------------------------------------------------------------------
# Step 5: Compile with CORRECT type — should SUCCEED (verifies the fix)
# ---------------------------------------------------------------------------
echo "--- Step 5: Compile with CORRECT type (verify the fix) ---"
cat > "${TMPDIR}/test_correct_type.c" << 'BPFEOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* Fixed code uses trace_event_raw_sched_wakeup_template which matches the
   kernel's vmlinux BTF definition. */
SEC("tracepoint/sched/sched_wakeup")
int test_wakeup_correct(struct trace_event_raw_sched_wakeup_template *ctx) {
    return ctx->pid;
}

SEC("tracepoint/sched/sched_wakeup_new")
int test_wakeup_new_correct(struct trace_event_raw_sched_wakeup_template *ctx) {
    return ctx->pid;
}
BPFEOF

CORRECT_OUTPUT=$(clang -O2 -target bpf -D__TARGET_ARCH_x86 \
    -I"${TMPDIR}" \
    -c "${TMPDIR}/test_correct_type.c" \
    -o "${TMPDIR}/test_correct_type.o" 2>&1)
CORRECT_EXIT=$?

if [ $CORRECT_EXIT -eq 0 ] && [ -f "${TMPDIR}/test_correct_type.o" ]; then
    pass "Compilation with correct type trace_event_raw_sched_wakeup_template SUCCEEDED"
else
    fail "Compilation with correct type trace_event_raw_sched_wakeup_template should have succeeded"
    echo "  Output: $CORRECT_OUTPUT"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
TOTAL=$((PASS + FAIL + SKIP))
echo "  Total: $TOTAL  Passed: $PASS  Failed: $FAIL  Skipped: $SKIP"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi
