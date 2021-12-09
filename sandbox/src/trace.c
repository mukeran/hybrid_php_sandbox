#include "trace.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>

#include "util.h"

struct syscall_info {
    uint64_t id;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
};

void get_registers(pid_t ch, struct user_regs_struct *regs) {
    ptrace(PTRACE_GETREGS, ch, NULL, regs);
}

void set_registers(pid_t ch, struct user_regs_struct *regs) {
    ptrace(PTRACE_SETREGS, ch, NULL, regs);
}

void parse_syscall_params(const struct user_regs_struct *regs, struct syscall_info *out) {
    out->id   = regs->orig_rax;
    out->arg1 = regs->rdi;
    out->arg2 = regs->rsi;
    out->arg3 = regs->rdx;
    out->arg4 = regs->r10;
    out->arg5 = regs->r8;
    out->arg6 = regs->r9;
}

char *get_memory_string(pid_t pid, uint64_t addr) {
    char buf[PATH_MAX];
    sprintf(buf, "/proc/%d/mem", pid);
    FILE *fp = fopen(buf, "r");
    if (fp == NULL) {
        fprintf(stderr, "Open %s failed.\n", buf);
        return NULL;
    }
    fseek(fp, addr, SEEK_SET);
    int i = 0;
    while (1) {
        buf[i] = fgetc(fp);
        if (buf[i] == 0 || i >= PATH_MAX || feof(fp))
            break;
        i++;
    }
    fclose(fp);
    char *p = malloc(sizeof(char) * (i + 1));
    memcpy(p, buf, sizeof(char) * (i + 1));
    return p;
}

void on_syscall(pid_t pid, int type) {
    struct user_regs_struct regs;
    struct syscall_info info;

    get_registers(pid, &regs);

    if (type == 0) {
        parse_syscall_params(&regs, &info);
        char *pathname;
        int fd;
        uint64_t flags, mode;
        struct report *report = build_syscall_report(info.id);
        send_to_server(report);
        free_report(report);
        switch (info.id) {
        case SYS_execve:
            if (info.arg1 != 0) {
                pathname = get_memory_string(pid, info.arg1);
                if (pathname != NULL) {
#ifdef DEBUG
                    printf("[trace_loop][PID: %d] Syscall execve pathname: %s\n", pid, pathname);
#endif
                    report = new_report(SUSPICIOUS_SYSCALL, 0);
                    report_append_uint32(report, info.id);
                    report_append_data(report, pathname, strlen(pathname));
                    complete_report(report);
                    send_to_server(report);
                    free_report(report);
                    free(pathname);
                }
            }
            break;
        case SYS_execveat:
            if (info.arg2 != 0) {
                pathname = get_memory_string(pid, info.arg2);
                if (pathname != NULL) {
#ifdef DEBUG
                    printf("[trace_loop][PID: %d] Syscall execveat pathname: %s\n", pid, pathname);
#endif
                    report = new_report(SUSPICIOUS_SYSCALL, 0);
                    report_append_uint32(report, info.id);
                    report_append_data(report, pathname, strlen(pathname));
                    complete_report(report);
                    send_to_server(report);
                    free_report(report);
                    free(pathname);
                }
            }
            break;
        case SYS_open:
            if (info.arg1 != 0) {
                pathname = get_memory_string(pid, info.arg1);
                flags = info.arg2;
                mode = info.arg3;
#ifdef DEBUG
                printf("[trace_loop][PID: %d] Syscall open pathname: %s, flags: %lu, mode: %lu\n", pid, pathname, flags, mode);
#endif
                report = new_report(SUSPICIOUS_SYSCALL, 0);
                report_append_uint32(report, info.id);
                report_append_uint16(report, strlen(pathname));
                report_append_data(report, pathname, strlen(pathname));
                report_append_uint32(report, flags);
                report_append_uint32(report, mode);
                complete_report(report);
                send_to_server(report);
                free_report(report);
                free(pathname);
                break;
            }
        case SYS_openat:
            pathname = get_memory_string(pid, info.arg2);
            flags = info.arg3;
            mode = info.arg4;
#ifdef DEBUG
            printf("[trace_loop][PID: %d] Syscall openat pathname: %s, flags: %lu, mode: %lu", pid, pathname, flags, mode);
            fd = info.arg1;
            if (fd == AT_FDCWD)
                printf(", fd is cwd");
            putchar('\n');
#endif
            report = new_report(SUSPICIOUS_SYSCALL, 0);
            report_append_uint32(report, info.id);
            report_append_uint16(report, strlen(pathname));
            report_append_data(report, pathname, strlen(pathname));
            report_append_uint32(report, flags);
            report_append_uint32(report, mode);
            complete_report(report);
            send_to_server(report);
            free_report(report);
            free(pathname);
            break;
        }
    }
}

void setup_trace() {
    kill(getpid(), SIGSTOP);
}

struct simple_map *insyscall_map;

void trace_loop(pid_t pid) {
    insyscall_map = new_simple_map();
    int status;
    while (waitpid(pid, &status, WSTOPPED) < 0) {
        if (errno == EINTR)
            continue;
        fprintf(stderr, "waitpid failed!\n");
        kill(pid, SIGKILL);
        exit(-1);
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "Unexpected wait stattus %#x", status);
        kill(pid, SIGKILL);
        exit(-1);
    }
    if (ptrace(PTRACE_SEIZE, pid, 0L, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK)) {
        fprintf(stderr, "PTRACE_SEIZE error, errno: %d\n", errno);
        kill(pid, SIGKILL);
        exit(-1);
    }
    if (ptrace(PTRACE_INTERRUPT, pid, 0L, 0L)) {
        fprintf(stderr, "PTRACE_INTERRUPT error\n");
        kill(pid, SIGKILL);
        exit(-1);
    }
    kill(pid, SIGCONT);
    while (1) {
        int status;
        pid_t child = waitpid((pid_t)(-1), &status, __WALL);
        if (errno == ECHILD) {
            errno = 0;
            continue;
        }
        /** Track SIGTRAP (syscall) */
        unsigned int stopsig = WSTOPSIG(status);
        int syscallstop = (stopsig == (SIGTRAP | 0x80));
        if (syscallstop) {
            int insyscall = simple_map_get(insyscall_map, child);
            on_syscall(child, insyscall), insyscall = !insyscall;
            simple_map_set(insyscall_map, child, insyscall);
        }
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
}
