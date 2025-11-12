# 传入架构
ARCH ?= 

# 获取 libgmssl.so 的真实文件路径
GMSSL_REAL_FILE := $(shell readlink -f /usr/local/lib/libgmssl.so 2>/dev/null || echo "notfound")

# 获取实际架构
GMSSL_ARCH := $(shell \
	if [ -f $(GMSSL_REAL_FILE) ]; then \
		file $(GMSSL_REAL_FILE) | grep -q 'x86-64' && echo amd64 || echo arm64; \
	else \
		echo unknown; \
	fi \
)

# 交叉编译器选择
ifeq ($(ARCH),arm64)
	CC_TOOLCHAIN := aarch64-linux-gnu-gcc
else ifeq ($(ARCH),amd64)
	CC_TOOLCHAIN := x86_64-linux-gnu-gcc
else
	$(error Unsupported ARCH: $(ARCH))
endif

all: check_arch

check_arch:
	@if [ "$(GMSSL_ARCH)" != "$(ARCH)" ]; then \
		echo "架构不一致或未知，开始重建..."; \
		$(MAKE) rebuild_gmssl ARCH=$(ARCH); \
		cp ./GmSSL-master/build/bin/libgmssl.so* ../lib; \
		cp ./GmSSL-master/build/bin/libgmssl.so* ../src/crypto/lib; \
		$(MAKE) rebuild_softsdf ARCH=$(ARCH); \
		cp ./SoftSDF-main/build/libsoftsdf.so ../lib;\
		cp ./SoftSDF-main/build/libsoftsdf.so ../src/crypto/lib;\
	else \
		cp ./GmSSL-master/build/bin/libgmssl.so* ../lib; \
		cp ./GmSSL-master/build/bin/libgmssl.so* ../src/crypto/lib; \
		cp ./SoftSDF-main/build/libsoftsdf.so ../lib;\
		cp ./SoftSDF-main/build/libsoftsdf.so ../src/crypto/lib;\
		echo "架构一致，跳过GmSSL、SoftSDF"; \
	fi \

rebuild_gmssl:
	@echo "重建 GmSSL..."
	@cd ./GmSSL-master && rm -rf build && mkdir build && cd build && \
	cmake .. -DCMAKE_C_COMPILER=$(CC_TOOLCHAIN) && \
	make && make install
	@echo "GmSSL 重建完成。"

rebuild_softsdf:
	@echo "重建 SoftSDF..."
	@cd ./SoftSDF-main && rm -rf build && mkdir build && cd build && \
	cmake .. -DCMAKE_C_COMPILER=$(CC_TOOLCHAIN) && \
	make
	@echo "SoftSDF 重建完成。"
