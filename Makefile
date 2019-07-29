CC=gcc
CFLAGS_NO_WARNINGS= -ggdb -w -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF

BUILD_DIR=build/
SRC_DIR=src/
TEST_DIR=testdir/

SOURCES=base64.c bcrypt.c
TEST_SOURCES=openbsd.c
OBJS=bcrypt.o


.PHONY: all clean

test: $(TEST_DIR)main.c $(SOURCES) $(TEST_SOURCES) $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)$@
	./build/test

bcrypt.o: bcrypt.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

blowfish.o: blowfish.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

build:
	mkdir build

clean:
	rm -f *.o
	rm -rf build


vpath %.o build
vpath %.c src
vpath %.c testdir
vpath %.asm src