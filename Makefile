.POSIX:

# Directory names
BUILD=build/
CORE=core/
CRACKER=cracker/
INCLUDE=include/
TEST=test/
UTILS=utils/

# Command line
CC=gcc
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
CFLAGS_NO_WARNINGS= -ggdb -w -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
INC_DIRS=$(CORE) $(CRACKER) $(TEST) $(UTILS)
INC_PARAMS=$(foreach d, $(INC_DIRS), -I$(INCLUDE)$d)
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF


SOURCES=$(CORE)bcrypt.c $(UTILS)base64.c $(UTILS)print.c $(CRACKER)cracker-common.c
SOURCES_PARALLEL=$(CORE)bcrypt-parallel.c $(UTILS)base64.c $(UTILS)print.c
CRACKER_SOURCES=$(UTILS)config.c $(CRACKER)cracker-common.c
TEST_SOURCES=$(TEST)openbsd.c $(TEST)test.c
OBJS=bcrypt.o loaded-p-test-wrappers.o
OBJS_NO_UNROLLING=bcrypt-no-unrolling.o loaded-p-test-wrappers.o
OBJS_LOADED_P=bcrypt-loaded-p.o loaded-p-test-wrappers.o
OBJS_PARALLEL=bcrypt-parallel.o parallel-test-wrappers.o
OBJS_LOADED_P_NO_PENALTIES=bcrypt-loaded-p-no-penalties.o loaded-p-no-penalties-test-wrappers.o
OBJS_TESTING=bcrypt-macro-testing.o


.PHONY: all build test

all: clean cracker encrypt


# Crackers

cracker: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt.o $(OBJS)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-no-unrolling: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-no-unrolling.o $(OBJS_NO_UNROLLING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-loaded-p: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-loaded-p.o $(OBJS_LOADED_P)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-parallel: $(CRACKER)cracker-parallel.c $(SOURCES_PARALLEL) $(CRACKER_SOURCES) variant-bcrypt-parallel.o $(OBJS_PARALLEL)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@


# Aligned crackers

cracker-aligned: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-aligned.o bcrypt-aligned.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-no-unrolling-aligned: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-no-unrolling.o bcrypt-no-unrolling-aligned.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-loaded-p-aligned: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-loaded-p.o bcrypt-loaded-p-aligned.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-parallel-aligned: $(CRACKER)cracker-parallel.c $(SOURCES_PARALLEL) $(CRACKER_SOURCES) variant-bcrypt-parallel.o bcrypt-parallel-aligned.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@


# No AVX-SSE penalties cracker

cracker-loaded-p-no-penalties: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-loaded-p-no-penalties.o $(OBJS_LOADED_P)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@


# Utilities and tests

encrypt: $(CORE)encrypt.c $(SOURCES) $(OBJS)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

test: $(TEST)single.c $(SOURCES) $(TEST_SOURCES) variant-bcrypt.o $(OBJS) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test

test-no-unrolling: $(TEST)single.c $(SOURCES) $(TEST_SOURCES) variant-bcrypt-no-unrolling.o $(OBJS_NO_UNROLLING) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-no-unrolling

test-loaded-p: $(TEST)single.c $(SOURCES) $(TEST_SOURCES) variant-bcrypt-loaded-p.o $(OBJS_LOADED_P) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-loaded-p

test-loaded-p-no-penalties: $(TEST)single.c $(SOURCES) $(TEST_SOURCES) variant-bcrypt-loaded-p-no-penalties.o $(OBJS_LOADED_P_NO_PENALTIES) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-loaded-p-no-penalties

test-parallel: $(TEST)parallel.c $(TEST_SOURCES) variant-bcrypt-parallel.o $(OBJS) $(OBJS_PARALLEL) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-parallel

b64encode: $(UTILS)main.c $(UTILS)base64.c
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@


# Basic bcrypt object code

bcrypt.o: $(CORE)bcrypt.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-no-unrolling.o: $(CORE)bcrypt-no-unrolling.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-loaded-p.o: $(CORE)bcrypt-loaded-p.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-parallel.o: $(CORE)bcrypt-parallel.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt.o: $(CORE)variant/variant-bcrypt.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-no-unrolling.o: $(CORE)variant/variant-bcrypt-no-unrolling.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-loaded-p.o: $(CORE)variant/variant-bcrypt-loaded-p.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-parallel.o: $(CORE)variant/variant-bcrypt-parallel.asm build
	$(NASM) $(NASMFLAGS) $< -o $@


# Aligned object code

bcrypt-aligned.o: $(CORE)bcrypt-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-no-unrolling-aligned.o: $(CORE)bcrypt-no-unrolling-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-loaded-p-aligned.o: $(CORE)bcrypt-loaded-p-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-parallel-aligned.o: $(CORE)bcrypt-parallel-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-aligned.o: $(CORE)variant/variant-bcrypt-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-no-unrolling-aligned.o: $(CORE)variant/variant-bcrypt-no-unrolling-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-loaded-p-aligned.o: $(CORE)variant/variant-bcrypt-loaded-p-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-parallel-aligned.o: $(CORE)variant/variant-bcrypt-parallel-aligned.asm build
	$(NASM) $(NASMFLAGS) $< -o $@


# No AVX-SSE penalties object code

bcrypt-loaded-p-no-penalties.o: $(CORE)bcrypt-loaded-p-no-penalties.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-loaded-p-no-penalties.o: $(CORE)variant/variant-bcrypt-loaded-p-no-penalties.asm build
	$(NASM) $(NASMFLAGS) $< -o $@


# Wrapper object code

loaded-p-test-wrappers.o: $(TEST)loaded-p-test-wrappers.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

parallel-test-wrappers.o: $(TEST)parallel-test-wrappers.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

bcrypt-macro-testing.o: $(TEST)bcrypt-macro-testing.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

loaded-p-no-penalties-test-wrappers.o: $(TEST)loaded-p-no-penalties-test-wrappers.asm build
	$(NASM) $(NASMFLAGS) $< -o $@


# Commands

build:
	if [ ! -d "./build" ]; then mkdir build; fi

clean:
	rm -f *.o
	rm -rf build


vpath %.o build
vpath %.c src
vpath %.asm src