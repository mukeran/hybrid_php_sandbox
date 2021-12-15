#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

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

void free_report(struct report *report) {
    if (report == NULL)
        return;
    if (report->data != NULL)
        free(report->data);
    free(report);
}

int send_to_server(struct report *report) {
    if (access("/run/server.sock", F_OK) == -1)
        return -1;
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, "/run/server.sock", 17);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
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

void report_append_data(struct report *report, const unsigned char *data, int length) {
    check_report_size(report, length);
    memcpy(report->data + report->length, data, length);
    report->length += length;
}

struct report *build_php_function_call_report(const char *function_name) {
    struct report *report = new_report(PHP_FUNCTION_CALL, 0);
    report_append_data(report, function_name, strlen(function_name));
    complete_report(report);
    return report;
}

struct report *build_php_suspicious_function_call_report(const char *function_name, const char *params, int params_length) {
    struct report *report = new_report(SUSPICIOUS_PHP_FUNCTION_CALL, 0);
    int function_name_length = strlen(function_name);
    report_append_uint16(report, function_name_length);
    report_append_data(report, function_name, function_name_length);
    report_append_data(report, params, params_length);
    complete_report(report);
    return report;
}