
CFLAGS = -g -O -Wall -Werror -fPIC -DPIC -I../

BUILD ?= build

all: $(BUILD)/pam_enclave.so $(BUILD)/enclave.bin

$(BUILD)/enclave.bin:
	$(MAKE) -C enclave all

$(BUILD)/pam_enclave.so: pam_enclave.c $(BUILD)
	@echo CC $<
	@$(CROSS_COMPILE)gcc $(CFLAGS) -shared -rdynamic -o $@ pam_enclave.c

$(BUILD):
	@echo MKDIR $@
	@mkdir -p $(BUILD)

test: pam_enclave.so
	pamtester testing ubuntu chauthtok authenticate

install: pam_enclave.so pam.d.testing
	install -m 0644 pam.d.testing /etc/pam.d/testing
	install pam_enclave.so /lib/x86_64-linux-gnu/security/pam_enclave.so

clean:
	@echo CLEAN
	@rm -fr build *.so *.o

uninstall:
	@echo UNINSTALL
	@sudo rm -fv /lib/x86_64-linux-gnu/security/pam_enclave.so
	@sudo rm -fv /lib/x86_64-linux-gnu/security/pam_ignore.so
	@sudo rm -fv /etc/pam.d/testing
