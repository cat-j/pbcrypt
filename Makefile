.POSIX:

# Directory names
BUILD=build/
CORE=core/
INCLUDE=include/
TEST=test/
UTILS=utils/

# Command line
CC=gcc
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
CFLAGS_NO_WARNINGS= -ggdb -w -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
INC_DIRS=$(CORE) $(TEST) $(UTILS)
INC_PARAMS=$(foreach d, $(INC_DIRS), -I$(INCLUDE)$d)
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF


SOURCES=$(CORE)bcrypt.c $(UTILS)base64.c
TEST_SOURCES=$(TEST)openbsd.c
OBJS=bcrypt.o


.PHONY: all clean build test

all: clean cracker

cracker: $(CORE)main.c $(SOURCES) $(OBJS)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

test: $(TEST)main.c $(SOURCES) $(TEST_SOURCES) $(OBJS)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test

b64encode: $(UTILS)main.c $(UTILS)base64.c
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

bcrypt.o: $(CORE)bcrypt.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

build:
	if [ ! -d "./build" ]; then mkdir build; fi

clean:
	rm -f *.o
	rm -rf build


vpath %.o build
vpath %.c src
vpath %.asm src