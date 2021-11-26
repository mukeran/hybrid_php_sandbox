test -d modules && \
/root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool mkdir -p /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/lib/php/extensions/no-debug-non-zts-20170718
echo "Installing shared extensions:     /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/lib/php/extensions/no-debug-non-zts-20170718/"
rm -f modules/*.la >/dev/null 2>&1
/root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c modules/* /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/lib/php/extensions/no-debug-non-zts-20170718
if test ""; then \
	for i in `echo `; do \
		i=`/root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool path -d $i`; \
		paths="$paths /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i"; \
	done; \
	/root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool mkdir -p $paths && \
	echo "Installing header files:          /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/" && \
	for i in `echo `; do \
		if test "php_sandbox"; then \
			src=`echo $i | /usr/bin/sed -e "s#ext/php_sandbox/##g"`; \
		else \
			src=$i; \
		fi; \
		if test -f "/root/Projects/hybrid_php_sandbox/sandbox/extension/$src"; then \
			/root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 /root/Projects/hybrid_php_sandbox/sandbox/extension/$src /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i; \
		elif test -f "/root/Projects/hybrid_php_sandbox/sandbox/extension/$src"; then \
			/root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 /root/Projects/hybrid_php_sandbox/sandbox/extension/$src /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i; \
		else \
			(cd /root/Projects/hybrid_php_sandbox/sandbox/extension/$src && /root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 *.h /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i; \
			cd /root/Projects/hybrid_php_sandbox/sandbox/extension/$src && /root/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 *.h /root/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i) 2>/dev/null || true; \
		fi \
	done; \
fi
