test -d modules && \
/opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool mkdir -p /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/lib/php/extensions/no-debug-non-zts-20170718
echo "Installing shared extensions:     /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/lib/php/extensions/no-debug-non-zts-20170718/"
rm -f modules/*.la >/dev/null 2>&1
/opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c modules/* /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/lib/php/extensions/no-debug-non-zts-20170718
if test ""; then \
	for i in `echo `; do \
		i=`/opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool path -d $i`; \
		paths="$paths /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i"; \
	done; \
	/opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool mkdir -p $paths && \
	echo "Installing header files:          /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/" && \
	for i in `echo `; do \
		if test "php_sandbox"; then \
			src=`echo $i | /usr/bin/sed -e "s#ext/php_sandbox/##g"`; \
		else \
			src=$i; \
		fi; \
		if test -f "/opt/Projects/hybrid_php_sandbox/sandbox/extension/$src"; then \
			/opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 /opt/Projects/hybrid_php_sandbox/sandbox/extension/$src /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i; \
		elif test -f "/opt/Projects/hybrid_php_sandbox/sandbox/extension/$src"; then \
			/opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 /opt/Projects/hybrid_php_sandbox/sandbox/extension/$src /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i; \
		else \
			(cd /opt/Projects/hybrid_php_sandbox/sandbox/extension/$src && /opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 *.h /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i; \
			cd /opt/Projects/hybrid_php_sandbox/sandbox/extension/$src && /opt/Projects/hybrid_php_sandbox/sandbox/extension/build/shtool install -c -m 644 *.h /opt/Projects/hybrid_php_sandbox/sandbox/extension/rootfs/usr/local/include/php/$i) 2>/dev/null || true; \
		fi \
	done; \
fi
