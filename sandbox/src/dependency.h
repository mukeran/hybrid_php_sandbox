#ifndef _DEPENDENCY_H
#define _DEPENDENCY_H

int is_elf_file(const char *filename);
int get_section(char *dst, const char *filename, const char *section_name);
int get_dependencies(char **dst, const char *filename);

#endif