all: libsimpleloader.so

libsimpleloader.so: sum.c loader.c
	gcc -m32 -shared -o $@ $^ -nostdlib -no-pie

clean:
	-@rm -f libsimpleloader.so
