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

#endif