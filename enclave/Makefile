# Assumes: $(ENCLAVE_SRC_DIR)

BUILD_DIR ?= ../build
CROSS_COMPILE ?= riscv64-unknown-linux-gnu-
SM ?= ../../security_monitor

CFLAGS := -march=rv64g -mcmodel=medany -mabi=lp64 -fno-common -std=gnu11 -Wall -Werror -O -g
LDFLAGS := -nostartfiles -nostdlib -static

CC = $(CROSS_COMPILE)gcc
OBJCOPY = $(CROSS_COMPILE)objcopy

API_DIR = ../../

ENCLAVE_ELF := $(BUILD_DIR)/enclave.elf
ENCLAVE_BIN := $(BUILD_DIR)/enclave.bin

ENCLAVE_INCLUDES := \
	$(PLATFORM_DIR) \
	$(API_DIR)

ENCLAVE_COMMON_SRC := \
	enclave_entry.S \
	enclave_main.c \
	$(SM)/src/clib/strcmp.c \
	enclave_stack.S

all: enclave

ENCLAVE_LD := enclave.lds
.INTERMEDIATE: $(SM_LD)

$(ENCLAVE_ELF): $(ENCLAVE_COMMON_SRC) $(ENCLAVE_LD) $(BUILD_DIR)
	@echo BUILD $@ 
	@$(CC) $(CFLAGS) $(addprefix -I , $(ENCLAVE_INCLUDES)) $(LDFLAGS) -T $(ENCLAVE_LD) $< $(ENCLAVE_COMMON_SRC) -o $@

$(ENCLAVE_BIN): $(ENCLAVE_ELF)
	@echo OBJCOPY $@
	@$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata --only-section=.data --only-section=.bss $< $@

$(BUILD_DIR):
	@echo MKDIR $@
	@mkdir -p $(BUILD_DIR)

.PHONY: enclave
enclave : $(ENCLAVE_BIN)
