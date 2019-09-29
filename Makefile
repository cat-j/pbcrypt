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


SOURCES=$(CORE)bcrypt.c $(UTILS)base64.c $(UTILS)print.c
CRACKER_SOURCES=$(UTILS)config.c $(CORE)cracker-common.c
TEST_SOURCES=$(TEST)openbsd.c $(TEST)test.c
OBJS=bcrypt.o loaded-p-test-wrappers.o
OBJS_NO_UNROLLING=bcrypt-no-unrolling.o loaded-p-test-wrappers.o
OBJS_LOADED_P=bcrypt-loaded-p.o loaded-p-test-wrappers.o
OBJS_PARALLEL=bcrypt-parallel.o
OBJS_TESTING=bcrypt-macro-testing.o


.PHONY: all build test

all: clean cracker encrypt

cracker: $(CORE)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt.o $(OBJS)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-no-unrolling: $(CORE)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-no-unrolling.o $(OBJS_NO_UNROLLING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-parallel: $(CORE)cracker-parallel.c $(CRACKER_SOURCES) variant-bcrypt-parallel.o $(OBJS_PARALLEL)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

encrypt: $(CORE)encrypt.c $(SOURCES) $(OBJS)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

test: $(TEST)single.c $(SOURCES) $(TEST_SOURCES) variant-bcrypt.o $(OBJS) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test

test-no-unrolling: $(TEST)single.c $(SOURCES) $(TEST_SOURCES) variant-bcrypt-no-unrolling.o $(OBJS_NO_UNROLLING) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-no-unrolling

test-loaded-p: $(TEST)single.c $(SOURCES) $(TEST_SOURCES) variant-bcrypt-loaded-p.o $(OBJS_LOADED_P) $(OBJS_TESTING)
	$(CC) $(CFLAGS_NO_WARNINGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-loaded-p

test-parallel: $(TEST)parallel.c $(TEST_SOURCES) variant-bcrypt-parallel.o $(OBJS) $(OBJS_PARALLEL) $(OBJS_TESTING)
	$(CC) $(CFLAGS_NO_WARNINGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-parallel

b64encode: $(UTILS)main.c $(UTILS)base64.c
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

bcrypt.o: $(CORE)bcrypt.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-no-unrolling.o: $(CORE)bcrypt-no-unrolling.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-loaded-p.o: $(CORE)bcrypt-loaded-p.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-parallel.o: $(CORE)bcrypt-parallel.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

loaded-p-test-wrappers.o: $(TEST)loaded-p-test-wrappers.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-macro-testing.o: $(TEST)bcrypt-macro-testing.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt.o: $(CORE)/variant/variant-bcrypt.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-no-unrolling.o: $(CORE)/variant/variant-bcrypt-no-unrolling.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-loaded-p.o: $(CORE)/variant/variant-bcrypt-loaded-p.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-parallel.o: $(CORE)/variant/variant-bcrypt-parallel.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

build:
	if [ ! -d "./build" ]; then mkdir build; fi

clean:
	rm -f *.o
	rm -rf build


vpath %.o build
vpath %.c src
vpath %.asm src