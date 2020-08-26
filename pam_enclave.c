/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Include PAM headers */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include <security_monitor/api/api.h>

struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; };
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct run_enclave*)

int call_enclave(pam_handle_t * pamh, const char *user, const char *password) {
    int fd = 0;
    struct arg_start_enclave val;
    fd = open("/dev/security_monitor", O_RDWR);
    if (fd < 0) {
        return PAM_IGNORE;
    }
    FILE *ptr;
    const char *enclave_bin_name = "/ssith/pam-enclave.bin";
    ptr = fopen(enclave_bin_name,"rb");
    struct stat statbuf;
    stat(enclave_bin_name, &statbuf);
    off_t sizefile = statbuf.st_size;
    char* enclave = memalign(1<<12,sizefile);
    size_t sizecopied = fread(enclave, sizefile, 1, ptr);
    if (sizecopied < sizefile) {
      if (sizecopied < 0)
          fprintf(stderr, "Error reading enclave binary: %s\n", strerror(errno));
      else
          fprintf(stderr, "Failed to read enclave binary: size read %ld expected %ld\n", sizecopied, sizefile);
    }
    fclose(ptr);

    /* Allocate memory to share with the enclave. Need to find a proper place for that */
#define begin_shared 0xF000000
#define shared_size 0x1000
    char* shared_enclave = (char *)mmap((void *)begin_shared, shared_size, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // 
    if (shared_enclave == MAP_FAILED) {
        perror("Shared memory not allocated in a correct place, last errno: ");
        return PAM_IGNORE;
    }

    memset(shared_enclave, 0, shared_size);
    snprintf(shared_enclave, shared_size, "%s\n%s\n", user, password);

    val.enclave_start = (long)enclave;
    val.enclave_end = (long)(enclave + sizefile - 4096); // last page contains nonces and measurement
    int ret = ioctl(fd, IOCTL_START_ENCLAVE, &val);

    int response = PAM_AUTH_ERR;
    if (ret == 0) {
        fprintf(stderr, "Received from enclave: %s\n", shared_enclave); 
        if (strcmp(shared_enclave, "authorized") == 0)
            response = PAM_SUCCESS;
    } else {
        fprintf(stderr, "IOCTL error: %s\n", strerror(errno));
    }

    memset(shared_enclave, 0, shared_size);
    munmap(shared_enclave, shared_size);
    close(fd);
    return response;
}

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for authentication verification */

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    char *password = NULL;
    int pgu_ret, pp_ret, ce_ret;

    pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL) {
        return(PAM_IGNORE);
    }

    pp_ret = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &password, "Password: ");
    if (pp_ret != PAM_SUCCESS) {
	_pam_overwrite(password);
        return PAM_IGNORE;
    }

    ce_ret = call_enclave(pamh, user, password);
    _pam_overwrite(password);

    return ce_ret;
}

/*
  PAM entry point for setting user credentials (that is, to actually
  establish the authenticated user's credentials to the service provider)
*/
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_IGNORE);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    const char *authtok = NULL;
    int pgu_ret, pgi_ret;

    pgu_ret = pam_get_user(pamh, &user, NULL);
    if (pgu_ret != PAM_SUCCESS || user == NULL) {
        return(PAM_IGNORE);
    }
    pam_syslog(pamh, LOG_AUTH|LOG_NOTICE, "user %s\n", user);

    pgi_ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&authtok);
    if (pgi_ret != PAM_SUCCESS || authtok == NULL) {
        return(PAM_IGNORE);
    }

    return(PAM_SUCCESS);
}

