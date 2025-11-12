.PHONY: all check_arch rebuild_nist_sts

ARCH ?=
# 目标静态库路径
NIST_STS_LIB := ./build/nist_sts/libnist_sts.so

# 检测静态库架构
NIST_STS_ARCH := $(shell \
	if [ -f $(NIST_STS_LIB) ]; then \
		file $(NIST_STS_LIB) | grep -q 'x86-64' && echo amd64 || echo arm64; \
	else \
		echo unknown; \
	fi \
)

# 交叉编译器
ifeq ($(ARCH),arm64)
	CC_TOOLCHAIN := aarch64-linux-gnu-gcc
else ifeq ($(ARCH),amd64)
	CC_TOOLCHAIN := x86_64-linux-gnu-gcc
else
	$(error Unsupported ARCH: $(ARCH))
endif

all: check_arch

check_arch:
	@if [ "$(NIST_STS_ARCH)" != "$(ARCH)" ]; then \
		echo "架构不一致或未检测到，开始重建 nist_sts..."; \
		$(MAKE) rebuild_nist_sts ARCH=$(ARCH); \
		cp ./build/nist_sts/libnist_sts.so ../../../lib/; \
		else \
		cp ./build/nist_sts/libnist_sts.so ../../../lib/; \
		echo "架构一致，跳过NIST_STS"; \
	fi \

rebuild_nist_sts:
	@echo "开始重建 nist_sts..."
	@rm -rf build && mkdir -p build && cd build && \
	cmake .. -DCMAKE_C_COMPILER=$(CC_TOOLCHAIN) && \
	make
	@echo "nist_sts 重建完成。"