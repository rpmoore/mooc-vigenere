all: dec.c
	gcc -g -std=c99 dec.c -o dec

run: all
	./dec

clean:
	rm dec
