BINDIR = ./bin
# 依赖
CDEPENDS = installdeps
CRYPTO_LIB_NAME ?= softsdf
ARCH ?=

# 加密服务
SRCDIR1 = ./src/cserver
TARGET1 = cryptoserver

# 管理服务
SRCDIR2 = ./src/mserver
TARGET2 = manageserver

# Linux简易管理工具
SRCDIR3 = ./src/managetool
TARGET3 = managetool

# 客户端库
CLIENTDIR = ./clientSDF
TARGET4 = clientSDFso

# 代理服务
SRCDIR5 = ./src/mserAgent
TARGET5 = mserAgent

# 配置文件修改
UPDATE_CONFIG = update_config

# 默认加密库配置
PROJECT_ROOT := $(shell pwd)
CRYPTO_LIB_DIR  ?= $(PROJECT_ROOT)/src/crypto/lib
CRYPTO_RPATH    ?= $(shell pwd)/lib

DB_TAGS=mysql
CRYPTO_HARDWARE=$(CRYPTO_LIB_NAME)
BUILD_TAGS=-tags="${DB_TAGS},${CRYPTO_HARDWARE}"

# 检测包管理器
ifeq ($(shell command -v apt-get 2> /dev/null),)
  ifeq ($(shell command -v yum 2> /dev/null),)
    $(error "Unsupported package manager, only apt/yum supported")
  else
    PKG_MGR := yum
  endif
else
  PKG_MGR := apt
endif


# 根据架构设置包名和编译器
ifeq ($(ARCH),amd64)
  GCC_PKG := gcc-x86-64-linux-gnu
  CHECK_CMD := which x86_64-linux-gnu-gcc
  CC := x86_64-linux-gnu-gcc
else ifeq ($(ARCH),arm64)
  GCC_PKG := gcc-aarch64-linux-gnu
  CHECK_CMD := which aarch64-linux-gnu-gcc
  CC := aarch64-linux-gnu-gcc
else
  $(error "Unsupported ARCH: $(ARCH), use amd64/arm64")
endif


build: clean all
all: $(CDEPENDS) \
	 $(UPDATE_CONFIG) \
 	 $(BINDIR)/$(TARGET1) \
	 $(BINDIR)/$(TARGET2) \
	 $(BINDIR)/$(TARGET3) \
	 $(TARGET4) \
	 $(BINDIR)/$(TARGET5)

# 交叉编译工具
$(CDEPENDS):
	@echo "Checking for $(GCC_PKG)..."
	@if ! $(CHECK_CMD) > /dev/null 2>&1; then \
        echo "Installing $(GCC_PKG)..."; \
        if [ "$(PKG_MGR)" = "apt" ]; then \
            sudo apt-get update && sudo apt-get install -y $(GCC_PKG); \
        elif [ "$(PKG_MGR)" = "yum" ]; then \
            sudo yum install -y $(GCC_PKG); \
    	fi; \
        if ! $(CHECK_CMD) > /dev/null 2>&1; then \
            echo "Installation failed, please install $(GCC_PKG) manually"; \
            exit 1; \
        fi; \
    else \
        echo "$(GCC_PKG) already installed"; \
	fi;
# 软算法库
	make -C ./source/ ARCH=$(ARCH);
	@echo "make crypto lib done!"
# 随机数检测库
	make -C ./src/initialize/nist_sts ARCH=$(ARCH);
	@echo "make random check lib done!"



$(BINDIR)/$(TARGET1): $(SRCDIR1)/*.go
	cd $(SRCDIR1) && \
	CC=$(CC) CGO_ENABLED=1 CGO_LDFLAGS="-L$(CRYPTO_LIB_DIR) -l$(CRYPTO_LIB_NAME) -Wl,-rpath=$(CRYPTO_RPATH)" \
	GOARCH=$(ARCH) go build -o $(TARGET1) $(BUILD_TAGS) 
	mv $(SRCDIR1)/$(TARGET1) $(BINDIR)
	@echo "make $(TARGET1) done!"

$(BINDIR)/$(TARGET2):$(SRCDIR2)/*.go
	cd $(SRCDIR2) && \
	CC=$(CC) CGO_ENABLED=1 CGO_LDFLAGS="-L$(CRYPTO_LIB_DIR) -l$(CRYPTO_LIB_NAME) -Wl,-rpath=$(CRYPTO_RPATH)" \
	GOARCH=$(ARCH) go build -o $(TARGET2) $(BUILD_TAGS)
	mv $(SRCDIR2)/$(TARGET2) $(BINDIR)
	@echo "make $(TARGET2) done!"

$(BINDIR)/$(TARGET3):$(SRCDIR3)/*.go
	cd $(SRCDIR3) && \
	CC=$(CC) CGO_ENABLED=1 CGO_LDFLAGS="-L$(CRYPTO_LIB_DIR) -l$(CRYPTO_LIB_NAME) -Wl,-rpath=$(CRYPTO_RPATH)" \
	GOARCH=$(ARCH) go build -o $(TARGET3) $(BUILD_TAGS)
	mv $(SRCDIR3)/$(TARGET3) $(BINDIR)
	@echo "make $(TARGET3) done!"

$(TARGET4):
	make -C $(CLIENTDIR)
	@echo "make $(TARGET4) done!"

$(BINDIR)/$(TARGET5):$(SRCDIR5)/*.go
	cd $(SRCDIR5) && \
	CC=$(CC) CGO_ENABLED=1 CGO_LDFLAGS="-L$(CRYPTO_LIB_DIR) -l$(CRYPTO_LIB_NAME) -Wl,-rpath=$(CRYPTO_RPATH)" \
	GOARCH=$(ARCH) go build -o $(TARGET5) $(BUILD_TAGS)
	mv $(SRCDIR5)/$(TARGET5) $(BINDIR)
	@echo "make $(TARGET5) done!"

$(UPDATE_CONFIG):
ifeq ($(CRYPTO_LIB_NAME),softsdf)
	@echo "Setting PROKEY_ENCTYPE to CBC"
	@sed -i 's/^\([[:space:]]*PROKEY_ENCTYPE[[:space:]]*=[[:space:]]*\).*/\1CBC/' $(BINDIR)/config.conf
else ifeq ($(CRYPTO_LIB_NAME),swsds)
	@echo "Setting PROKEY_ENCTYPE to ECB"
	@sed -i 's/^\([[:space:]]*PROKEY_ENCTYPE[[:space:]]*=[[:space:]]*\).*/\1ECB/' $(BINDIR)/config.conf
else
	@echo "Unknown CRYPTO_LIB_NAME value: $(CRYPTO_LIB_NAME)"
	@exit 1
endif

clean:
	@pkill $(TARGET1);\
	pkill $(TARGET2);\
	pkill $(TARGET3);\
	rm -rf $(BINDIR)/$(TARGET1) $(BINDIR)/$(TARGET2) $(BINDIR)/$(TARGET3) 
