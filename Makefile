CC=gcc
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF
VPATH=./src:./test:../src:./build

BUILD_DIR=build
SRC_DIR=src
TEST_DIR=testdir

vpath $(VPATH)

test: $(TEST_DIR)/main.c $(BUILD_DIR)/bcrypt.o $(TEST_DIR)/openbsd.c
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/$@

bcrypt: $(SRC_DIR)/main.c bcrypt.o
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/$@

testexec: main.c blowfish.o
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/$@

bcrypt.o: bcrypt.asm
	$(NASM) $(NASMFLAGS) $< -o $(BUILD_DIR)/$@

blowfish.o: blowfish.asm
	$(NASM) $(NASMFLAGS) $< -o $(BUILD_DIR)/$@

clean:
	rm -f *.o
	rm -f testexec bcrypt
	rm -rf build