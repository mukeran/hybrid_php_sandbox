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
#include <sys/socket.h>
#include <sys/un.h>

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

int starts_with(const char *a, const char *b) {
   if(strncmp(a, b, strlen(b)) == 0) return 1;
   return 0;
}

char* read_link_path(const char* path) {
    struct stat sb;
    char *linkname;
    ssize_t r;
    if (lstat(path, &sb) == -1) {
        fprintf(stderr, "lstat failed.\n");
        return NULL;
    }
    linkname = malloc(sb.st_size + 1);
    if (linkname == NULL) {
        fprintf(stderr, "insufficient memory.\n");
        return NULL;
    }
    r = readlink(path, linkname, sb.st_size + 1);
    if (r < 0) {
        fprintf(stderr, "readlink failed.\n");
        return NULL;
    }
    if (r > sb.st_size + 1) {
        fprintf(stderr, "symlink increased in size between lstat() and readlink()\n");
        return NULL;
    }
    linkname[sb.st_size] = '\0';
    return linkname;
}

void free_report(struct report *report) {
    if (report == NULL)
        return;
    if (report->data != NULL)
        free(report->data);
    free(report);
}

int send_to_server(struct report *report) {
#ifdef DEBUG
    FILE *fp = fopen("/run/server.log", "a+");
    fprintf(fp, "access: %d\n", access("/run/server.sock", F_OK));
#endif
    if (access("/run/server.sock", F_OK) == -1) {
#ifdef DEBUG
        fclose(fp);
#endif
        return -1;
    }
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, "/run/server.sock", 17);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
#ifdef DEBUG
        fprintf(fp, "Failed to connect to server.sock\n");
        fclose(fp);
#endif
        fprintf(stderr, "Failed to connect to server.sock\n");
        return -1;
    }
#ifdef DEBUG
    fclose(fp);
#endif
    int n = send(sock, report->data, report->length, 0);
    close(sock);
    return n;
}

#define TYPE_BYTE 1
#define LENGTH_BYTES 2
#define DATA_CAPACITY_INCREMENT 0xff

struct report *new_report(unsigned char type, int data_length_indication) {
    struct report *report = (struct report *)malloc(sizeof(struct report));
    if (data_length_indication == 0)
        data_length_indication = DATA_CAPACITY_INCREMENT;
    else
        data_length_indication += TYPE_BYTE + LENGTH_BYTES;
    report->size = data_length_indication;
    report->length = TYPE_BYTE + LENGTH_BYTES;
    report->data = (unsigned char *)malloc(report->size);
    *report->data = type;
    return report;
}

void complete_report(struct report *report) {
    *(unsigned short *)(report->data + 1) = htobe16(report->length);
}

void check_report_size(struct report *report, int append_length) {
    if (report->length + append_length > report->size) {
        report->size = ((report->length + append_length) / DATA_CAPACITY_INCREMENT + 1) * DATA_CAPACITY_INCREMENT;
        report->data = (unsigned char *)realloc(report->data, report->size);
    }
}

void report_append_uint8(struct report *report, unsigned char i) {
    check_report_size(report, 1);
    *(report->data + report->length) = i;
    ++report->length;
}

void report_append_uint16(struct report *report, unsigned short i) {
    check_report_size(report, 2);
    *(unsigned short *)(report->data + report->length) = htobe16(i);
    report->length += 2;
}

void report_append_uint32(struct report *report, unsigned int i) {
    check_report_size(report, 4);
    *(unsigned int *)(report->data + report->length) = htobe32(i);
    report->length += 4;
}

void report_append_data(struct report *report, unsigned char *data, int length) {
    check_report_size(report, length);
    memcpy(report->data + report->length, data, length);
    report->length += length;
}

struct report *build_syscall_report(int syscall) {
    struct report *report = new_report(SYSCALL, 4);
    report_append_uint32(report, syscall);
    complete_report(report);
    return report;
}

#define MAP_CAPACITY_INCREMENT 100

struct simple_map *new_simple_map() {
    struct simple_map *map = (struct simple_map *)malloc(sizeof(struct simple_map));
    map->cap = MAP_CAPACITY_INCREMENT;
    map->len = 0;
    map->key = (int *)malloc(map->cap);
    map->value = (int *)malloc(map->cap);
    return map;
}

void simple_map_set(struct simple_map *map, int key, int value) {
    int i, found = 0;
    for (i = 0; i < map->len; ++i)
        if (map->key[i] == key) {
            found = 1;
            map->value[i] = value;
            break;
        }
    if (!found) {
        if (map->len >= map->cap) {
            map->cap += MAP_CAPACITY_INCREMENT;
            map->key = (int *)realloc(map->key, map->cap);
            map->value = (int *)realloc(map->value, map->cap);
        }
        map->key[map->len] = key;
        map->value[map->len] = value;
        ++map->len;
    }
}

int simple_map_get(struct simple_map *map, int key) {
    int i;
    for (i = 0; i < map->len; ++i)
        if (map->key[i] == key)
            return map->value[i];
    return 0;
}

void free_simple_map(struct simple_map *map) {
    if (map == NULL)
        return;
    if (map->key != NULL) {
        free(map->key);
        map->key = NULL;
    }
    if (map->value != NULL) {
        free(map->value);
        map->value = NULL;
    }
    free(map);
}
