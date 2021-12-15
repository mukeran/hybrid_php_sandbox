C_SOURCES = $(wildcard src/*.c)
OBJ = ${C_SOURCES:.c=.o}
HEADERS = $(wildcard src/*.h)

CC = gcc ${EXTRA}
LD = ld

all: sandbox
.PHONY: php extension clean setup_user

run: all
	./sandbox

debug: clean
	EXTRA="-g -DDEBUG" make all

notrace: clean
	EXTRA="-g -DNOTRACE" make all

debug_notrace: clean
	EXTRA="-g -DDEBUG -DNOTRACE" make all

%.o: %.c ${HEADERS}
	${CC} -c $< -o $@

sandbox: ${OBJ}
	${LD} -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o $@ /usr/lib/x86_64-linux-gnu/crt1.o /usr/lib/x86_64-linux-gnu/crti.o $^ -lc /usr/lib/x86_64-linux-gnu/crtn.o

clean:
	rm -rf ${OBJ}
	rm -rf sandbox
	rm -rf rootfs

php:
	cd php && ./configure --prefix=/usr/local --with-curl --with-gd --with-mysqli --with-openssl --with-pdo-mysql --with-pdo-sqlite --with-pear --with-zlib --enable-fpm --enable-xml --enable-zip --enable-sockets --enable-soap --enable-pcntl --enable-mbstring && \
	make -j$(shell nproc) && \
	make -n install > make_install.sh && \
	chmod +x make_install.sh && \
	sed -i s/\\/usr\\/local/$(shell pwd | sed -e s/\\//\\\\\\//g)\\/rootfs\\/usr\\/local/g make_install.sh && \
	./make_install.sh

extension:
	cd extension && phpize && ./configure && \
	make && \
	make -n install > make_install.sh && \
	chmod +x make_install.sh && \
	sed -i s/\\/usr\\/local/$(shell pwd | sed -e s/\\//\\\\\\//g)\\/rootfs\\/usr\\/local/g make_install.sh && \
	./make_install.sh

setup_user:
	sudo useradd hybrid-php-sandbox
