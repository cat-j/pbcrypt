CC=gcc
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF
VPATH=src:test:../src

BUILD_DIR=build
SRC_DIR=src
TEST_DIR=testdir

test: $(TEST_DIR)/main.c bcrypt.o $(TEST_DIR)/openbsd.c
	$(CC) $(CFLAGS) $^ -o $@

bcrypt: $(SRC_DIR)/main.c bcrypt.o
	$(CC) $(CFLAGS) $^ -o $@

testexec: main.c blowfish.o
	$(CC) $(CFLAGS) $^ -o $@

bcrypt.o: bcrypt.asm
	$(NASM) $(NASMFLAGS) $< -o $@

# openbsd.o: $(TEST_DIR)/openbsd.c
# 	$(CC) $(CFLAGS) $^ -o $@

blowfish.o: blowfish.asm
	$(NASM) $(NASMFLAGS) $< -o $@

clean:
	rm -f *.o
	rm -f testexec bcrypt