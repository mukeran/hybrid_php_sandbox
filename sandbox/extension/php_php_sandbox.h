/* php_sandbox extension for PHP */

#ifndef PHP_PHP_SANDBOX_H
# define PHP_PHP_SANDBOX_H

extern zend_module_entry php_sandbox_module_entry;
# define phpext_php_sandbox_ptr &php_sandbox_module_entry

# define PHP_PHP_SANDBOX_VERSION "0.1.0"

# if defined(ZTS) && defined(COMPILE_DL_PHP_SANDBOX)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_PHP_SANDBOX_H */
