#include "util.h"

#include <string.h>
#include <stdlib.h>

#define BURSIZE 4096

char dec2hex(short int c) {
    if (0 <= c && c <= 9) {
        return c + '0';
    }
    else if (10 <= c && c <= 15) {
        return c + 'A' - 10;
    }
    else {
        return -1;
    }
}

char *urlencode(const char *str) {
    int i = 0;
    int len = strlen(str);
    int res_len = 0;
    char res[BURSIZE];
    for (i = 0; i < len; ++i) {
        char c = str[i];
        if (('0' <= c && c <= '9') ||
            ('a' <= c && c <= 'z') ||
            ('A' <= c && c <= 'Z') ||
            c == '.') {
            res[res_len++] = c;
        }
        else if(c == ' ') {
            res[res_len++] = '+';
        }
        else {
            int j = (short int)c;
            if (j < 0)
                j += 256;
            int i1, i0;
            i1 = j / 16;
            i0 = j - i1 * 16;
            res[res_len++] = '%';
            res[res_len++] = dec2hex(i1);
            res[res_len++] = dec2hex(i0);
        }
    }
    res[res_len] = '\0';
    char *ret = malloc(sizeof(char) * (res_len + 1));
    memcpy(ret, res, sizeof(char) * (res_len + 1));
    return ret;
}
