#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include "mkroot.h"
#include "util.h"
#include "dependency.h"
#include "trace.h"

#define CONTAINER_STACK_SIZE (1024 * 1024)

static char container_stack[CONTAINER_STACK_SIZE];

int container_pid;
char *container_cwd;
char *execution_id;
char *rootfs_path;

char *container_execv_args[] = {
    "/usr/bin/tail",
    "-f",
    "/dev/null",
    NULL
};

char *php_fpm_execv_args[] = {
    "/usr/local/sbin/php-fpm",
    "--allow-to-run-as-root",
    "--nodaemonize"
};

char *debug_container_execv_args[] = {
    "/bin/bash",
    NULL
};

int on_user_mapped[2];

void handle_SIGSEGV () {
    printf("Sandbox reports segmentation fault! Exiting...\n");
    kill(-1, SIGTERM);
    kill(-1, SIGKILL);
    exit(10);
}

int container_main() {
    char path[PATH_MAX];
    /** Register SIGSEGV handler */
    signal(SIGSEGV, handle_SIGSEGV);
    close(on_user_mapped[1]);
    /** Change root */
    if (chdir(rootfs_path) != 0 || chroot("./") != 0){
        perror("Failed to chroot");
    }
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC, NULL) != 0) {
        perror("Failed to mount proc");
    }
    if (mount("none", "/tmp", "tmpfs", 0, NULL) != 0) {
        perror("Failed to mount tmp");
    }
    /** Change cwd */
    chdir(container_cwd);
    /** Set env */
    clearenv();
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("EXECUTION_ID", execution_id, 1);
    // close(on_initialized[1]);
    /** Setup ptrace */
#ifndef NOTRACE
    pid_t pid = fork();
    switch (pid) {
    case -1:
        fprintf(stderr, "Failed to fork");
        break;
    case 0:
        setup_trace();
#endif
        /** Wait for sandbox_user mapped inside */
        char _useless;
        read(on_user_mapped[0], &_useless, 1);
        if (setgid(0) != 0) {
            fprintf(stderr, "Failed to setgid to %d\n", 0);
        }
        if (setuid(0) != 0) {
            fprintf(stderr, "Failed to setuid to %d\n", 0);
        }
        /** Start php-fpm */
        execv(php_fpm_execv_args[0], php_fpm_execv_args);
        // execv(debug_container_execv_args[0], debug_container_execv_args);
#ifndef NOTRACE
    default:
#ifdef DEBUG
        printf("Tracer PID: %d\n", getpid());
        printf("Tracee PID: %d\n", pid);
#endif
        trace_loop(pid);
        break;
    }
#endif
    return 0;
}

void terminate_sandbox(int sig) {
    printf("Attempt to terminate sandbox\n");
    if (container_pid != 0) {
        kill(-container_pid, SIGTERM);
        kill(-container_pid, SIGKILL);
    }
    exit(-3);
}

int setup_checkpoints() {
    if (pipe(on_user_mapped) == -1)
        return -1;
    return 0;
}

int mapping_uid_gid(uid_t uid, gid_t gid) {
    char *path = (char *)malloc(PATH_MAX);
    sprintf(path, "/proc/%d/uid_map", container_pid);
    int mapping_uid = open(path, O_WRONLY);
    if (mapping_uid == -1) {
        fprintf(stderr, "Failed to open %s\n", path);
        free(path);
        return -1;
    }
    sprintf(path, "0 %d 1\n65534 65534 1\n", uid);
    if (write(mapping_uid, path, strlen(path)) < 0) {
        fprintf(stderr, "Failed to write uid_map\n");
        free(path);
        return -1;
    }
    close(mapping_uid);
    sprintf(path, "/proc/%d/gid_map", container_pid);
    int mapping_gid = open(path, O_WRONLY);
    if (mapping_gid == -1) {
        fprintf(stderr, "Failed to open %s\n", path);
        free(path);
        return -1;
    }
    sprintf(path, "0 %d 1\n65534 65534 1\n", gid);
    if (write(mapping_gid, path, strlen(path)) < 0) {
        fprintf(stderr, "Failed to write gid_map\n");
        free(path);
        return -1;
    }
    close(mapping_gid);
    free(path);
}

int main(int argc, char *argv[]) {
#ifdef DEBUG
    printf("Current PID: %d\n", getpid());
    printf("Parent PID: %d\n", getppid());
#endif
    /** Set execution id and rootfs path */
    if (argc > 1) {
        int len = strlen(argv[1]);
        rootfs_path = (char *)malloc(len + 1);
        memcpy(rootfs_path, argv[1], len + 1);
        len = strlen(argv[2]);
        execution_id = (char *)malloc(len + 1);
        memcpy(execution_id, argv[2], len + 1);
    } else {
        rootfs_path = (char *)malloc(9);
        memcpy(rootfs_path, "./rootfs", 9);
        execution_id = (char *)malloc(7);
        memcpy(execution_id, "000000", 7);
    }
    if (access(rootfs_path, F_OK) == 0) {
        fprintf(stderr, "Path for rootfs %s exists, please delete it first to continue", rootfs_path);
        return -1;
    }
    mkdir_recursively(rootfs_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    /** Make root */
    mkroot(rootfs_path);
    /** Set cwd */
    char *value = getenv("SANDBOX_CWD");
    if (value == NULL) {
        container_cwd = malloc(sizeof(char) * PATH_MAX);
        memcpy(container_cwd, "/", 2);
    } else {
        value = strdup(value);
        int len = strlen(value);
        container_cwd = malloc(sizeof(char) * (len + 1));
        memcpy(container_cwd, value, sizeof(char) * (len + 1));
        free(value);
    }
    /** Get run user */
    struct passwd *sandbox_user;
    value = getenv("SANDBOX_USER");
    if (value == NULL) {
        value = (char *)malloc(19);
        memcpy(value, "hybrid-php-sandbox", 19);
    }
    value = strdup(value);
    sandbox_user = getpwnam(value);
    if (sandbox_user == NULL) {
        fprintf(stderr, "Invalid sandbox user %s, please run make setup-user to create a sandbox user or check environment variable SANDBOX_USER\n", value);
        free(value);
        return -1;
    }
    free(value);
    /** Change owner of rootfs to sandbox_user */
    value = (char *)malloc(PATH_MAX);
    sprintf(value, "chown -R %d:%d %s", sandbox_user->pw_uid, sandbox_user->pw_gid, rootfs_path);
    system(value);
    free(value);
    /** Start sandbox */
    if (setup_checkpoints() == -1) {
        fprintf(stderr, "Failed to setup checkpoints\n");
        return -1;
    }
    signal(SIGINT, terminate_sandbox);
    container_pid = clone(container_main, container_stack + CONTAINER_STACK_SIZE, CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER | SIGCHLD, NULL);
#ifdef DEBUG
    printf("Container PID: %d\n", container_pid);
#endif
    close(on_user_mapped[0]);
    /** Mapping uid and gid to sandbox_user */
    mapping_uid_gid(sandbox_user->pw_uid, sandbox_user->pw_gid);
    close(on_user_mapped[1]);
    /** Wait for container to exit */
    waitpid(container_pid, NULL, 0);
    free(execution_id);
    return 0;
}
