#include <string.h>
#include "security_monitor/api/api_enclave.h"

void enclave_entry() {
  void* shared_begin = (void *)0xF000000;
  const char *usernamepassword = "ubuntu\nfred\n";
  int result = strcmp(shared_begin,usernamepassword);
  if (result == 0) {
    strcpy(shared_begin,"authorized");
  } else {
    strcpy(shared_begin,"failed");
  }

  sm_exit_enclave();
}

