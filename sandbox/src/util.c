#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>

/** Join paths */
void path_join(char *dst, int n, ...) {
    va_list list;
    va_start(list, n);
    for (int i = 0; i < n; ++i) {
        char *arg = va_arg(list, char*);
        int len = strlen(arg);
        if (i != 0) {
            *dst = '/';
            ++dst;
        }
        memcpy(dst, arg, sizeof(char) * len);
        dst += len;
    }
    *dst = '\0';
    va_end(list);
}

/** Check if directory is empty */
int is_directory_empty(const char *dirname) {
    DIR *dir = opendir(dirname);
    struct dirent *file;
    if (dir == NULL) {
        fprintf(stderr, "Failed to opendir %s\n", dirname);
        return -1;
    }
    while (1) {
        file = readdir(dir);
        if (file <= 0) break;
        if (strcmp(".", file->d_name) == 0 || strcmp("..", file->d_name) == 0) continue;
        return -1;
    }
    return 0;
}

/** Simplely copy file */
int copy_file(char *from, char *to) {
    char buf[1024];
    int len;
    int fd_from, fd_to;
    fd_from = open(from, O_RDONLY);
    if (fd_from <= 0) {
        fprintf(stderr, "Failed to open source file %s\n", from);
        return -1;
    }
    fd_to = open(to, O_RDWR | O_CREAT);
    if (fd_to <= 0) {
        fprintf(stderr, "Failed to create dest file %s\n", to);
        return -1;
    }
    while (len = read(fd_from, buf, 1024)) {
        write(fd_to, buf, len);
    }
    struct stat st;
    stat(from, &st);
    chmod(to, st.st_mode);
    close(fd_from);
    close(fd_to);
    return 0;
}

int trim(char *str) {
    int len = strlen(str);
    char *head = str;
    while (head != 0 && (*head == ' ' || *head == '\t' || *head == '\n' || *head == '\r'))
        ++head;
    char *tail = str + len - 1;
    while (tail != head && (*tail == ' ' || *tail == '\t' || *tail == '\n' || *tail == '\r'))
        --tail;
    int i;
    for (i = 0; i < len && head <= tail; ++i, ++head)
        str[i] = *head;
    str[i] = '\0';
    return i;
}

void mkdir_recursively(const char *dir, mode_t mode) {
    if (access(dir, F_OK) == 0) return;
    char *dup_dir = strdup(dir);
    if (dup_dir == NULL) return;
    char *next_dir = dirname(dup_dir);
    // if (strcmp(next_dir, ".") == 0 || strcmp(next_dir, "/") == 0) {
    //     free(dup_dir);
    //     return;
    // }
    mkdir_recursively(next_dir, mode);
    free(dup_dir);
    if (mkdir(dir, mode) != 0) {
        fprintf(stderr, "Failed to mkdir %s\n", dir);
        return;
    }
}

int is_numeric(const char *str) {
    int len = strlen(str);
    for (int i = 0; i < len; ++i) {
        if (str[i] < '0' || str[i] > '9')
            return 0;
    }
    return 1;
}

int starts_with(const char *a, const char *b)
{
   if(strncmp(a, b, strlen(b)) == 0) return 1;
   return 0;
}

char* read_link_path(const char* path)
{
    struct stat sb;
    char *linkname;
    ssize_t r;

    if (lstat(path, &sb) == -1) {
        fprintf(stderr, "lstat failed.\n");
    }

   linkname = malloc(sb.st_size + 1);
    if (linkname == NULL) {
        fprintf(stderr, "insufficient memory.\n");
    }

   r = readlink(path, linkname, sb.st_size + 1);

   if (r < 0) {
        fprintf(stderr, "readlink failed.\n");
    }

   if (r > sb.st_size + 1) {
    //    fprintf(stderr, "%d %d\n", r, sb.st_size);
        fprintf(stderr, "symlink increased in size "
                        "between lstat() and readlink()\n");
    }

   linkname[sb.st_size] = '\0';
   return linkname;
}
