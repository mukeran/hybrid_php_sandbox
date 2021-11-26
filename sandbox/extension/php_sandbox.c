/* php_sandbox extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_php_sandbox.h"
#include "SAPI.h"
#include <arpa/inet.h>
#include <sys/socket.h>

#include "util.h"

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

#define hook_function_count 7
char *hook_function_names[] = {"system", "exec", "passthru", "shell_exec", "pcntl_exec", "popen", "mail"};
zif_handler original_functions[hook_function_count];
zif_handler original_cdef_function;

void inform_detected(const char *info) {
    if (PG(auto_globals_jit)) {
        zend_is_auto_global_str(ZEND_STRL("_SERVER"));
    }
    zval *_server = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    zval *_request_id = zend_hash_str_find(Z_ARRVAL_P(_server), "REQUEST_ID", sizeof("REQUEST_ID") - 1);
    if (_request_id == NULL)
        return;
    char *request_id = Z_STRVAL_P(_request_id);
    int listen_port = 9001;
    char *listen_port_env = getenv("PROXY_LISTEN_PORT");
    if (listen_port_env != NULL)
        sscanf(listen_port_env, "%d", &listen_port);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(listen_port);
    connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    char content[1024];
    char *urlencoded_info = urlencode(info);
    sprintf(content, "GET /%s?info=%s HTTP/1.1\r\n\r\n", request_id, urlencoded_info);
    free(urlencoded_info);
    write(sockfd, content, strlen(content));
    close(sockfd);
}

PHP_FUNCTION(hooked_system)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	php_printf("BLOCKED system!");
    char buf[2048];
    sprintf(buf, "system, command: %s", command);
    inform_detected(buf);
	RETURN_STRING("BLOCKED!")
}

PHP_FUNCTION(hooked_exec)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	php_printf("BLOCKED exec!");
    char buf[2048];
    sprintf(buf, "exec, command: %s", command);
    inform_detected(buf);
	RETURN_STRING("BLOCKED!")
}

PHP_FUNCTION(hooked_passthru)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	php_printf("BLOCKED passthru!");
    char buf[2048];
    sprintf(buf, "passthru, command: %s", command);
    inform_detected(buf);
	RETURN_STRING("BLOCKED!")
}

PHP_FUNCTION(hooked_shell_exec)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	php_printf("BLOCKED shell_exec!");
    char buf[2048];
    sprintf(buf, "shell_exec, command: %s", command);
    inform_detected(buf);
	RETURN_STRING("BLOCKED!")
}

PHP_FUNCTION(hooked_pcntl_exec)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	php_printf("BLOCKED pcntl_exec!");
    char buf[2048];
    sprintf(buf, "pcntl_exec, command: %s", command);
    inform_detected(buf);
	RETURN_STRING("BLOCKED!")
}

PHP_FUNCTION(hooked_popen)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	php_printf("BLOCKED popen!");
    char buf[2048];
    sprintf(buf, "popen, command: %s", command);
    inform_detected(buf);
	RETURN_STRING("BLOCKED!")
}

PHP_FUNCTION(hooked_mail)
{
    zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
    if (argc >= 4) {
        char buf[2048];
        sprintf(buf, "mail, argc >= 4");
        inform_detected(buf);
	    RETURN_STRING("BLOCKED!")
    } else {
        original_functions[6](execute_data, return_value);
    }
}

PHP_FUNCTION(hooked_cdef)
{
    zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
    char *func = Z_STRVAL(args[0]);
    char buf[2048];
    sprintf(buf, "FFI::cdef, func: %s", func);
    inform_detected(buf);
    RETURN_STRING("BLOCKED!")
}

zif_handler hook_functions[] = {zif_hooked_system, zif_hooked_exec, zif_hooked_passthru, zif_hooked_shell_exec, zif_hooked_pcntl_exec, zif_hooked_popen, zif_hooked_mail};

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(php_sandbox)
{
#if defined(ZTS) && defined(COMPILE_DL_PHP_SANDBOX)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(php_sandbox)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "php_sandbox support", "enabled");
	php_info_print_table_end();
}
/* }}} */

PHP_MINIT_FUNCTION(php_sandbox)
{
	/** Hook functions */
    for (int i = 0; i < hook_function_count; ++i) {
        zend_internal_function *func = zend_hash_str_find_ptr(CG(function_table), hook_function_names[i], strlen(hook_function_names[i]));
        if (func) {
            original_functions[i] = func->handler;
            func->handler = hook_functions[i];
        }
    }
    /** Hook FFI */
    zend_class_entry *class = zend_hash_str_find_ptr(CG(class_table), "ffi", 3);
    if (class) {
        zend_internal_function *func = zend_hash_str_find_ptr(&(class->function_table), "cdef", 4);
        if (func) {
            original_cdef_function = func->handler;
            func->handler = zif_hooked_cdef;
        }
    }
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(php_sandbox)
{
	for (int i = 0; i < hook_function_count; ++i) {
        zend_internal_function *func = zend_hash_str_find_ptr(CG(function_table), hook_function_names[i], strlen(hook_function_names[i]));
        if (func) {
            func->handler = original_functions[i];
        }
    }
	return SUCCESS;
}

/* {{{ php_sandbox_functions[]
 */
static const zend_function_entry php_sandbox_functions[] = {
	PHP_FE_END
};
/* }}} */

/* {{{ php_sandbox_module_entry
 */
zend_module_entry php_sandbox_module_entry = {
	STANDARD_MODULE_HEADER,
	"php_sandbox",					/* Extension name */
	php_sandbox_functions,			/* zend_function_entry */
	PHP_MINIT(php_sandbox),			/* PHP_MINIT - Module initialization */
	PHP_MSHUTDOWN(php_sandbox),		/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(php_sandbox),			/* PHP_RINIT - Request initialization */
	NULL,							/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(php_sandbox),			/* PHP_MINFO - Module info */
	PHP_PHP_SANDBOX_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_PHP_SANDBOX
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(php_sandbox)
#endif
