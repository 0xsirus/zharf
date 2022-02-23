all:
	gcc -Wall -Wno-varargs -fPIC -shared -O3 -o libzh.so libzh.c
	gcc -Wno-varargs -Wall -ozcc zcc.c
	gcc -Wall -Wno-varargs -Wunused-result -ozharf -rdynamic -O3 hash.c zharf.c
lib:
	gcc -Wall -Wno-varargs -fPIC -shared -O3 -olibzh.so libzh.c
zcc:
	gcc -Wall -ozcc zcc.c
zharf:
	gcc -Wall -Wno-varargs -Wunused-result -ozharf -rdynamic -O3 hash.c zharf.c
clean:
	rm -r libzh.so zharf zcc as /usr/local/zharf_helper
	rm /usr/bin/zharf
	rm /usr/bin/zcc
install:
	cp libzh.so /lib/x86_64-linux-gnu/
	cp zharf /usr/bin
	cp zcc /usr/bin
	ln -s zcc as
	ln -s zcc z++
	mkdir /usr/local/zharf_helper
	ln -s /usr/bin/zcc /usr/local/zharf_helper/as
