#ifndef _UTIL_H
#define _UTIL_H

char *urlencode(const char *str);

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
void report_append_data(struct report *report, const unsigned char *data, int length);
void free_report(struct report *report);
int send_to_server(struct report *report);
struct report *build_php_function_call_report(const char *function_name);
struct report *build_php_suspicious_function_call_report(const char *function_name, const char *params, int params_length);

#endif