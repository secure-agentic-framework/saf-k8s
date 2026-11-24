#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Only the recovery probe, getpid, changes disposition across the two filters. */
static int install_filter(int enforcing) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K,
                 enforcing ? (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)) : SECCOMP_RET_LOG),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = sizeof(code) / sizeof(code[0]), .filter = code };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "observe") && strcmp(argv[1], "enforce") &&
                      strcmp(argv[1], "recover"))) {
        fprintf(stderr, "usage: seccomp-proof observe|enforce|recover\n"); return 2;
    }
    if (!strcmp(argv[1], "recover")) {
        if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 0) {
            fputs("recovery process unexpectedly carries a seccomp filter\n", stderr);
            return 6;
        }
        long result = syscall(__NR_getpid);
        if (result <= 0) { perror("recovery getpid"); return 6; }
        puts("SAF-SC-RECOVERY: fresh unrestricted process completed getpid and output");
        return 0;
    }
    int enforcing = strcmp(argv[1], "enforce") == 0;
    pid_t pid = getpid();
    uid_t uid = getuid();
    printf("SAF-SC-TASK: mode=%s pid=%ld syscall=getpid\n", enforcing ? "enforce" : "observe", (long)pid);
    fflush(stdout);
    if (install_filter(enforcing) != 0) { perror("install_filter"); return 3; }

    if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER) {
        fputs("staging probe did not enter seccomp filter mode\n", stderr);
        return 7;
    }
    if (syscall(__NR_getuid) != (long)uid) {
        fputs("ordinary getuid syscall did not return the expected value\n", stderr);
        return 8;
    }
    puts("SAF-SC-ORDINARY: getuid succeeded under the selected filter");
    errno = 0;
    long result = syscall(__NR_getpid);
    if (enforcing) {
        if (result != -1 || errno != EPERM) {
            fprintf(stderr, "enforcing getpid expected EPERM, got result=%ld errno=%d\n", result, errno);
            return 4;
        }
        puts("SAF-SC-ENFORCE: getpid denied with EPERM; ordinary output succeeded");
    } else {
        if (result <= 0) { perror("observed getpid"); return 5; }
        puts("SAF-SC-OBSERVE: getpid returned successfully under LOG action");
    }
    return 0;
}
