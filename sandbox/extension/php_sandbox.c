/* php_sandbox extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_php_sandbox.h"
#include "SAPI.h"

#include "util.h"

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

#define hook_function_count 7
char *hook_function_names[] = {"system", "exec", "passthru", "shell_exec", "pcntl_exec", "popen", "putenv"};
zif_handler original_functions[hook_function_count];
zif_handler original_cdef_function;

zif_handler get_original_function(const char *function_name) {
	if (function_name == "FFI::cdef")
		return original_cdef_function;
	for (int i = 0; i < hook_function_count; ++i)
		if (strcmp(hook_function_names[i], function_name) == 0)
			return original_functions[i];
	return NULL;
}

PHP_FUNCTION(hooked_system)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	struct report *report = build_php_suspicious_function_call_report("system", command, strlen(command));
	send_to_server(report);
	free_report(report);
	(get_original_function("system"))(execute_data, return_value);
}

PHP_FUNCTION(hooked_exec)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	struct report *report = build_php_suspicious_function_call_report("exec", command, strlen(command));
	send_to_server(report);
	free_report(report);
	(get_original_function("exec"))(execute_data, return_value);
}

PHP_FUNCTION(hooked_passthru)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
    struct report *report = build_php_suspicious_function_call_report("passthru", command, strlen(command));
	send_to_server(report);
	free_report(report);
	(get_original_function("passthru"))(execute_data, return_value);
}

PHP_FUNCTION(hooked_shell_exec)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	struct report *report = build_php_suspicious_function_call_report("shell_exec", command, strlen(command));
	send_to_server(report);
	free_report(report);
	(get_original_function("shell_exec"))(execute_data, return_value);
}

PHP_FUNCTION(hooked_pcntl_exec)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	struct report *report = build_php_suspicious_function_call_report("pcntl_exec", command, strlen(command));
	send_to_server(report);
	free_report(report);
	(get_original_function("pcntl_exec"))(execute_data, return_value);
}

PHP_FUNCTION(hooked_popen)
{
	zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *command = Z_STRVAL(args[0]);
	struct report *report = build_php_suspicious_function_call_report("popen", command, strlen(command));
	send_to_server(report);
	free_report(report);
	(get_original_function("popen"))(execute_data, return_value);
}

PHP_FUNCTION(hooked_putenv)
{
    zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
	char *settings = Z_STRVAL(args[0]);
	if (strstr(settings, "LD_PRELOAD")) {
		struct report *report = build_php_suspicious_function_call_report("putenv", settings, strlen(settings));
		send_to_server(report);
		free_report(report);
	}
	(get_original_function("putenv"))(execute_data, return_value);
}

PHP_FUNCTION(hooked_cdef)
{
    zval *args = NULL;
	int argc = ZEND_NUM_ARGS();
	ZEND_PARSE_PARAMETERS_START(1, -1)
		Z_PARAM_VARIADIC('+', args, argc)
	ZEND_PARSE_PARAMETERS_END();
    char *func = Z_STRVAL(args[0]);
	char *so = Z_STRVAL(args[1]);
	char *buf = (char *)malloc(strlen(func) + strlen(so) + 1);
	int length = sprintf(buf, "%s|%s", func, so);
	struct report *report = build_php_suspicious_function_call_report("FFI::cdef", buf, length);
	free(buf);
	send_to_server(report);
	free_report(report);
	(get_original_function("FFI::cdef"))(execute_data, return_value);
}

zif_handler hook_functions[] = {zif_hooked_system, zif_hooked_exec, zif_hooked_passthru, zif_hooked_shell_exec, zif_hooked_pcntl_exec, zif_hooked_popen, zif_hooked_putenv};

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
	// php_info_print_table_header(2, "php_sandbox support", "enabled");
	php_info_print_table_end();
}
/* }}} */

static int hook_handler(zend_execute_data *execute_data) {
	if (execute_data->call == NULL || execute_data->call->func == NULL)
		return ZEND_USER_OPCODE_DISPATCH;
	if (execute_data->call->func->type != ZEND_INTERNAL_FUNCTION)
		return ZEND_USER_OPCODE_DISPATCH;
	zend_function *func = execute_data->call->func;
	zend_string *function_name = func->common.function_name;
	char *name;
	if (func->common.scope != NULL) {
		zend_string *class_name = func->common.scope->name;
		int function_name_length = ZSTR_LEN(function_name);
		int class_name_length = ZSTR_LEN(class_name);
		int length = function_name_length + class_name_length + 2 + 1;
		name = (char *)malloc(length);
		memcpy(name, ZSTR_VAL(class_name), class_name_length);
		memcpy(name + class_name_length, "::", 2);
		memcpy(name + class_name_length + 2, ZSTR_VAL(function_name), function_name_length);
		name[class_name_length + function_name_length + 2] = '\0';
	} else {
		int length = ZSTR_LEN(function_name) + 1;
		name = (char *)malloc(length);
		memcpy(name, ZSTR_VAL(function_name), length);
	}
	struct report *report = build_php_function_call_report(name);
	free(name);
	send_to_server(report);
	free_report(report);
	return ZEND_USER_OPCODE_DISPATCH;
}

PHP_MINIT_FUNCTION(php_sandbox)
{
	zend_set_user_opcode_handler(ZEND_DO_FCALL, hook_handler);
	zend_set_user_opcode_handler(ZEND_DO_ICALL, hook_handler);
	zend_set_user_opcode_handler(ZEND_DO_UCALL, hook_handler);
	zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, hook_handler);
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
	zend_set_user_opcode_handler(ZEND_DO_FCALL, NULL);
	zend_set_user_opcode_handler(ZEND_DO_ICALL, NULL);
	zend_set_user_opcode_handler(ZEND_DO_UCALL, NULL);
	zend_set_user_opcode_handler(ZEND_DO_FCALL_BY_NAME, NULL);
	/** Restore functions */
	for (int i = 0; i < hook_function_count; ++i) {
        zend_internal_function *func = zend_hash_str_find_ptr(CG(function_table), hook_function_names[i], strlen(hook_function_names[i]));
        if (func)
            func->handler = original_functions[i];
    }
	/** Restore FFI */
	zend_class_entry *class = zend_hash_str_find_ptr(CG(class_table), "ffi", 3);
    if (class) {
        zend_internal_function *func = zend_hash_str_find_ptr(&(class->function_table), "cdef", 4);
        if (func)
            func->handler = original_cdef_function;
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
