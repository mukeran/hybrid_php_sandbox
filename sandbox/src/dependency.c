#include "dependency.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <elf.h>

#include "util.h"

#define MAX_GET_SECTION_SIZE 128

int is_elf_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL)
        return 0;
    char buf[4];
    fread(buf, 1, 4, fp);
    return memcmp(buf, ELFMAG, 4) == 0;
}

int get_section(char *dst, const char *filename, const char *section_name) {
    Elf64_Ehdr elf_header;
    Elf64_Shdr *sh_table;
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) return -1;
    fread(&elf_header, 1, sizeof(Elf64_Ehdr), fp);
    sh_table = malloc(elf_header.e_shentsize * elf_header.e_shnum);

    fseek(fp, elf_header.e_shoff, SEEK_SET);
    fread(sh_table, 1, elf_header.e_shentsize * elf_header.e_shnum, fp);

    char *sh_str;
    sh_str = malloc(sh_table[elf_header.e_shstrndx].sh_size);
    fseek(fp, sh_table[elf_header.e_shstrndx].sh_offset, SEEK_SET);
    fread(sh_str, 1, sh_table[elf_header.e_shstrndx].sh_size, fp);
    for (int i = 0; i < elf_header.e_shnum; ++i) {
        if (strcmp(section_name, sh_str + sh_table[i].sh_name) == 0) {
            fseek(fp, sh_table[i].sh_offset, SEEK_SET);
            uint64_t size = min(MAX_GET_SECTION_SIZE - 1, sh_table[i].sh_size);
            fread(dst, 1, size, fp);
            dst[size] = '\0';
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int get_dependencies(char **dst, const char *filename) {
    char cmd[PATH_MAX + 50];
    sprintf(cmd, "LD_TRACE_LOADED_OBJECTS=1 %s", filename);
    FILE *fp = popen(cmd, "r");
    char buf[PATH_MAX * 2 + 50];
    int cnt = 0;
    while (cnt < 128) {
        fgets(buf, sizeof(buf)-1, fp);
        buf[sizeof(buf)-1] = '\0';
        if (feof(fp))
            break;
        trim(buf);
        char *head, *tail;
        if ((head = strstr(buf, "=>")) != NULL) {
            head = head + 2;
            trim(head);
        }
        else
            head = buf;
        tail = strchr(head, ' ');
        assert(tail != 0);
        dst[cnt] = malloc(tail - head + 1);
        memcpy(dst[cnt], head, tail - head);
        dst[cnt][tail - head] = '\0';
        ++cnt;
    }
    pclose(fp);
    return cnt;
}
