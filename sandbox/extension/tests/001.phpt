--TEST--
Check if php_sandbox is loaded
--SKIPIF--
<?php
if (!extension_loaded('php_sandbox')) {
	echo 'skip';
}
?>
--FILE--
<?php
echo 'The extension "php_sandbox" is available';
?>
--EXPECT--
The extension "php_sandbox" is available
