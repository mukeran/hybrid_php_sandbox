--TEST--
php_sandbox_test1() Basic test
--SKIPIF--
<?php
if (!extension_loaded('php_sandbox')) {
	echo 'skip';
}
?>
--FILE--
<?php
$ret = php_sandbox_test1();

var_dump($ret);
?>
--EXPECT--
The extension php_sandbox is loaded and working!
NULL
