all: main

main: tiny.so tiny.so.1 tinyagain.so
	ld -o main tiny.so tiny.so.1 tinyagain.so -lc

hello.o: hello.c
	gcc -c hello.c -o hello.o;

lib.so: lib.c
	gcc -shared lib.c -o lib.so;

clean:
	rm main
