CC=gcc
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF

BUILD_DIR = build

testexec: main.c blowfish.o
	$(CC) $(CFLAGS) $^ -o $@

blowfish.o: blowfish.asm
	$(NASM) $(NASMFLAGS) $< -o $@

clean:
	rm -f *.o
	rm -f testexec