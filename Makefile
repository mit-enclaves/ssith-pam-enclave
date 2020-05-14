
CFLAGS = -g -O -Wall -Werror -fPIC -DPIC -I../ -Ibuild

CROSS_COMPILE=riscv64-unknown-linux-gnu-

BUILD ?= build

all: $(BUILD)/pam_enclave.so $(BUILD)/enclave.bin

$(BUILD)/enclave.bin:
	$(MAKE) -C enclave all

$(BUILD)/pam_enclave.so: pam_enclave.c $(BUILD)
	@echo CC $<
	@cp -r /usr/include/security build
	@$(CROSS_COMPILE)gcc $(CFLAGS) -shared -rdynamic -o $@ pam_enclave.c

$(BUILD):
	@echo MKDIR $@
	@mkdir -p $(BUILD)

test: pam_enclave.so
	pamtester testing ubuntu chauthtok authenticate

install: $(BUILD)/pam_enclave.so pam.d.testing $(BUILD)/enclave.bin
	install -m 0644 pam.d.testing $(DESTDIR)/etc/pam.d/testing
	install $(BUILD)/pam_enclave.so $(DESTDIR)/lib/x86_64-linux-gnu/security/pam_enclave.so
	install $(BUILD)/enclave.bin $(DESTDIR)/test/enclave.bin

rootfs:
	mount ~/rootfs.ext2 /mnt
	rm -f /mnt/dev/null
	mknod /mnt/dev/null c 1 3 || true
	mknod /mnt/dev/console c 5 1 || true
	mknod /mnt/dev/ttyS0 c 4 64 || true
	mknod /mnt/dev/security_monitor c 10 62 || true
	install -m 0644 pam.d.testing /mnt/etc/pam.d/testing
	install $(BUILD)/pam_enclave.so /mnt/lib/security/pam_enclave.so
	mkdir -p /mnt/test
	install $(BUILD)/enclave.bin /mnt/test/enclave.bin
	umount /mnt

clean:
	@echo CLEAN
	@rm -fr build *.so *.o

uninstall:
	@echo UNINSTALL
	@sudo rm -fv /lib/x86_64-linux-gnu/security/pam_enclave.so
	@sudo rm -fv /lib/x86_64-linux-gnu/security/pam_ignore.so
	@sudo rm -fv /etc/pam.d/testing
