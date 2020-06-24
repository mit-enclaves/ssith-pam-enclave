#include <string.h>
#include <stdio.h> // snprintf
#include "security_monitor/api/api_enclave.h"
#include "security_monitor/src/clib/clib.h"

struct entry {
    char username[32];
    char password[32];
} entries[8] = {
  #include "entries.h"
};

char *strcpy(char *dest, const char *src)
{
    while (*src)
        *dest++ = *src++;
    return dest;
}

char *strcat(char *dest, const char *src)
{
    strcpy(dest + strlen(dest), src);
    return dest;
}

void enclave_entry() {
    char* shared_begin = (void *)0xF000000;
    struct entry entry;
    memset((char *)&entry, 0, sizeof(entry));
    int password_offset = -1;
    for (int i = 0; i < sizeof(entry.username) - 1; i++) {
        char c = shared_begin[i];
        if (c == '\n') {
            password_offset = i + 1;
            break;
        }
        entry.username[i] = c;
    }
    if (password_offset < 0) {
        strcpy(shared_begin,"invalid");
        sm_exit_enclave();
    }
    for (int i = 0; i < sizeof(entry.password) - 1; i++) {
        char c = shared_begin[password_offset + i];
        if (c == '\n') {
            break;
        }
        entry.password[i] = c;
    }

    int authenticated = 0;
    for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        int matches = (memncmp(entry.username, entries[i].username, sizeof(entry.username)) == 0)
            & (memncmp(entry.password, entries[i].password, sizeof(entry.password)) == 0);
        authenticated |= matches;
    }
    if (authenticated == 1) {
        strcpy(shared_begin,"authorized");
    } else {
	snprintf(shared_begin, 4096, "failed\n");
        //strcpy(shared_begin + 0, "failed");
    }

    sm_exit_enclave();
}

