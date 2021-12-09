#ifndef _UTIL_H
#define _UTIL_H

#include <sys/types.h>

#define min(a, b) (a < b ? a : b)

void path_join(char *dst, int n, ...);
int copy_file(char *from, char *to);
int is_directory_empty(const char *dirname);
int trim(char *str);
void mkdir_recursively(const char *dir, mode_t mode);
int is_numeric(const char *str);
int starts_with(const char *a, const char *b);
char* read_link_path(const char* path);

#define SYSCALL 1
#define PHP_FUNCTION_CALL 2
#define SUSPICIOUS_SYSCALL 3
#define SUSPICIOUS_PHP_FUNCTION_CALL 4

struct report {
    unsigned char *data;
    int size;
    int length;
};
struct report *new_report(unsigned char type, int data_length_indication);
void complete_report(struct report *report);
void check_report_size(struct report *report, int append_length);
void report_append_uint8(struct report *report, unsigned char i);
void report_append_uint16(struct report *report, unsigned short i);
void report_append_uint32(struct report *report, unsigned int i);
void report_append_data(struct report *report, unsigned char *data, int length);
void free_report(struct report *report);
int send_to_server(struct report *report);
struct report *build_syscall_report(int syscall);

struct simple_map {
    int cap;
    int len;
    int *key;
    int *value;
};

struct simple_map *new_simple_map();
void simple_map_set(struct simple_map *map, int key, int value);
int simple_map_get(struct simple_map *map, int key);
void free_simple_map(struct simple_map *map);

#endif
