all: sum fib loader lib_simpleloader.a

sum: sum.c
	gcc -m32 -no-pie -nostdlib -o sum sum.c

fib: fib.c
	gcc -m32 -no-pie -nostdlib -o fib fib.c

loader: loader.c
	gcc -m32 -o loader loader.c

lib_simpleloader.a: sum fib loader
	ar rcs lib_simpleloader.a sum fib loader

clean:
	-@rm -f sum fib loader lib_simpleloader.a
