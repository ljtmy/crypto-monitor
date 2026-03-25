LIBBPF_SRC ?= /usr/include
OUTPUT ?= build
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86
ARCH ?= x86

APP := $(OUTPUT)/crypto-monitor
BPF_OBJ := $(OUTPUT)/crypto_monitor.bpf.o
SKEL := $(OUTPUT)/crypto_monitor.skel.h
VMLINUX := src/bpf/vmlinux.h

.PHONY: all clean run fmt

all: $(APP)

$(VMLINUX):
	@mkdir -p $(dir $@)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): src/bpf/crypto_monitor.bpf.c src/common.h $(VMLINUX)
	@mkdir -p $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -I./src -I./src/bpf -c $< -o $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(APP): src/crypto-monitor.c src/common.h $(SKEL)
	$(CC) $(CFLAGS) -I./src -I$(OUTPUT) $< -o $@ -lbpf -lelf -lz

clean:
	rm -rf $(OUTPUT) $(VMLINUX)

fmt:
	clang-format -i src/crypto-monitor.c src/bpf/crypto_monitor.bpf.c src/common.h

run: $(APP)
	sudo $(APP)
