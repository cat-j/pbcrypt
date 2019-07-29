CC=gcc
CFLAGS_NO_WARNINGS= -ggdb -w -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF
VPATH=./src:./test:../src:./build

BUILD_DIR=build/
SRC_DIR=src/
TEST_DIR=testdir/

SOURCES=$(SRC_DIR)base64.c $(SRC_DIR)bcrypt.c
TEST_SOURCES=$(TEST_DIR)openbsd.c
OBJS=bcrypt.o


vpath %.o ./build/

test: $(TEST_DIR)main.c $(SOURCES) $(TEST_SOURCES) $(OBJS)
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)$@
	./build/test

bcrypt: $(SRC_DIR)main.c bcrypt.o
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)$@

bcrypt.o: bcrypt.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

blowfish.o: blowfish.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

build:
	mkdir build

clean:
	rm -f *.o
	rm -rf build