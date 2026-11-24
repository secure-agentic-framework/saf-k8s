#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define FIXTURE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define FIXTURE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__i386__)
#define FIXTURE_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__arm__)
#define FIXTURE_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64
#define FIXTURE_AUDIT_ARCH AUDIT_ARCH_RISCV64
#else
#error "Add an explicit audit architecture before building this fixture here"
#endif

static const int observed_syscalls[] = { SYS_getpid, SYS_getppid, SYS_getuid };

static void fail(const char *what)
{
    perror(what);
    exit(2);
}

static int send_listener(int socket_fd, int listener_fd)
{
    char byte = 'L';
    struct iovec iov = { .iov_base = &byte, .iov_len = sizeof(byte) };
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &listener_fd, sizeof(listener_fd));
    return sendmsg(socket_fd, &message, 0) == 1 ? 0 : -1;
}

static int receive_listener(int socket_fd)
{
    char byte;
    struct iovec iov = { .iov_base = &byte, .iov_len = sizeof(byte) };
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    if (recvmsg(socket_fd, &message, 0) != 1)
        return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int))) {
        errno = EPROTO;
        return -1;
    }
    int listener_fd;
    memcpy(&listener_fd, CMSG_DATA(header), sizeof(listener_fd));
    return listener_fd;
}

static int install_filter(const char *mode, const char *policy)
{
    struct sock_filter code[16];
    size_t used = 0;
#define APPEND(stmt) do { code[used++] = (struct sock_filter)stmt; } while (0)
    APPEND(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    APPEND(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIXTURE_AUDIT_ARCH, 1, 0));
    APPEND(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    APPEND(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

    if (strcmp(mode, "notify") == 0) {
        for (size_t i = 0; i < sizeof(observed_syscalls) / sizeof(observed_syscalls[0]); i++) {
            APPEND(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)observed_syscalls[i], 0, 1));
            APPEND(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
        }
        APPEND(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    } else {
        const int infrastructure[] = { SYS_exit_group, SYS_write };
        for (size_t i = 0; i < sizeof(infrastructure) / sizeof(infrastructure[0]); i++) {
            APPEND(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)infrastructure[i], 0, 1));
            APPEND(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
        FILE *rules = fopen(policy, "r");
        if (!rules)
            fail("open policy");
        int selected_pid = 0;
        int selected_uid = 0;
        char line[64];
        while (fgets(line, sizeof(line), rules)) {
            line[strcspn(line, "\r\n")] = '\0';
            int number;
            if (strcmp(line, "getpid") == 0 && !selected_pid) {
                number = SYS_getpid;
                selected_pid = 1;
            } else if (strcmp(line, "getuid") == 0 && !selected_uid) {
                number = SYS_getuid;
                selected_uid = 1;
            } else {
                fprintf(stderr, "invalid or duplicate fixture policy entry: %s\n", line);
                exit(2);
            }
            APPEND(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)number, 0, 1));
            APPEND(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
        if (ferror(rules))
            fail("read fixture policy");
        fclose(rules);
        APPEND(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
    }

    struct sock_fprog program = { .len = (unsigned short)used, .filter = code };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        strcmp(mode, "notify") == 0 ? SECCOMP_FILTER_FLAG_NEW_LISTENER : 0,
                        &program);
#undef APPEND
}

static long run_named(const char *name)
{
    if (strcmp(name, "getpid") == 0)
        return syscall(SYS_getpid);
    if (strcmp(name, "getppid") == 0)
        return syscall(SYS_getppid);
    if (strcmp(name, "getuid") == 0)
        return syscall(SYS_getuid);
    errno = EINVAL;
    return -1;
}

static const char *syscall_name(int number)
{
    if (number == SYS_getpid) return "getpid";
    if (number == SYS_getppid) return "getppid";
    if (number == SYS_getuid) return "getuid";
    return NULL;
}

static int observe(const char *operation)
{
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0)
        fail("socketpair");
    pid_t child = fork();
    if (child < 0)
        fail("fork");
    if (child == 0) {
        close(channel[0]);
        int listener = install_filter("notify", NULL);
        if (listener < 0)
            fail("install notification filter (needs seccomp user notification)");
        if (send_listener(channel[1], listener) != 0)
            fail("send listener");
        close(listener);
        long result = run_named(operation);
        _exit(result < 0 ? 3 : 0);
    }
    close(channel[1]);
    int listener = receive_listener(channel[0]);
    if (listener < 0)
        fail("receive listener");
    struct seccomp_notif request;
    struct seccomp_notif_resp response;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) != 0)
        fail("receive seccomp event");
    const char *name = syscall_name(request.data.nr);
    if (!name || strcmp(name, operation) != 0 || request.pid != (uint32_t)child ||
        request.data.arch != FIXTURE_AUDIT_ARCH) {
        fprintf(stderr, "collector received an unrecognized syscall or architecture\n");
        exit(2);
    }
    printf("OBSERVED %s\n", name);
    /* Continue only this owned child's fixed no-argument syscall. No production policy broker. */
    response.id = request.id;
    response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) != 0)
        fail("continue seccomp event");
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "synthetic notification probe failed\n");
        return 1;
    }
    close(listener);
    close(channel[0]);
    return 0;
}

static int enforce(const char *policy, const char *expectation)
{
    if (strcmp(expectation, "initial") != 0 && strcmp(expectation, "expanded") != 0)
        return 2;
    int uid_approved = strcmp(expectation, "expanded") == 0;
    if (install_filter("enforce", policy) < 0)
        fail("install enforcement filter");
    errno = 0;
    if (syscall(SYS_getpid) < 0) {
        fprintf(stderr, "approved getpid was denied\n");
        return 1;
    }
    errno = 0;
    long denied = syscall(SYS_getppid);
    if (denied != -1 || errno != EPERM) {
        fprintf(stderr, "incidental getppid was not denied with EPERM\n");
        return 1;
    }
    errno = 0;
    long uid = syscall(SYS_getuid);
    if (uid_approved ? uid < 0 : (uid != -1 || errno != EPERM)) {
        fprintf(stderr, "getuid result did not match the curated policy\n");
        return 1;
    }
    _exit(0);
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "observe") == 0)
        return observe(argv[2]);
    if (argc == 4 && strcmp(argv[1], "enforce") == 0)
        return enforce(argv[2], argv[3]);
    if (argc == 2 && strcmp(argv[1], "rollback") == 0) {
        if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 0 || run_named("getpid") < 0 || run_named("getppid") < 0 || run_named("getuid") < 0)
            return 1;
        puts("ROLLBACK fresh process is unrestricted");
        return 0;
    }
    fprintf(stderr, "usage: %s observe {getpid|getppid|getuid} | enforce POLICY {initial|expanded} | rollback\n", argv[0]);
    return 2;
}
