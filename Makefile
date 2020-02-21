# pbcrypt: parallel bcrypt for password cracking
# Copyright (C) 2019  Catalina Juarros <https://github.com/cat-j>

# This file is part of pbcrypt.

# pbcrypt is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.

# pbcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.

.POSIX:

# Directory names
BENCHMARK=benchmark/
BUILD=build/
CORE=core/
CRACKER=cracker/
INCLUDE=include/
TEST=test/
UTILS=utils/

# Command line
CC=gcc
CFLAGS= -ggdb -Wall -Wno-unused-parameter -Wextra -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L -Wno-stringop-truncation -Wno-stringop-overflow
CFLAGS_NO_WARNINGS= -ggdb -w -std=c99 -pedantic -m64 -no-pie -D_POSIX_C_SOURCE=200112L
INC_DIRS=$(BENCHMARK) $(CORE) $(CRACKER) $(TEST) $(UTILS)
INC_PARAMS=$(foreach d, $(INC_DIRS), -I$(INCLUDE)$d)
NASM=nasm
NASMFLAGS=-f elf64 -g -F DWARF


SOURCES=$(CORE)bcrypt.c $(UTILS)base64.c $(UTILS)print.c $(CRACKER)cracker-common.c
SOURCES_NO_CRACKER=$(CORE)bcrypt.c $(UTILS)base64.c $(UTILS)print.c
SOURCES_PARALLEL=$(CORE)bcrypt-parallel.c $(UTILS)base64.c $(UTILS)print.c
SOURCES_PARALLEL_DOUBLE=$(CORE)bcrypt-parallel-double.c $(UTILS)base64.c $(UTILS)print.c
CRACKER_SOURCES=$(UTILS)config.c $(CRACKER)cracker-common.c
TEST_SOURCES=$(TEST)openbsd.c $(TEST)test.c
OBJS=bcrypt.o loaded-p-test-wrappers.o
OBJS_NO_UNROLLING=bcrypt-no-unrolling.o loaded-p-test-wrappers.o
OBJS_LOADED_P=bcrypt-loaded-p.o loaded-p-test-wrappers.o
OBJS_PARALLEL=bcrypt-parallel.o parallel-test-wrappers.o
OBJS_PARALLEL_NO_VPERMQ=bcrypt-parallel-no-vpermq.o parallel-test-wrappers.o
OBJS_PARALLEL_DOUBLE=bcrypt-parallel-double.o parallel-double-test-wrappers.o
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

cracker-no-unrolling-aligned: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-no-unrolling-aligned.o bcrypt-no-unrolling-aligned.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-loaded-p-aligned: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-loaded-p-aligned.o bcrypt-loaded-p-aligned.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-parallel-aligned: $(CRACKER)cracker-parallel.c $(SOURCES_PARALLEL) $(CRACKER_SOURCES) variant-bcrypt-parallel-aligned.o bcrypt-parallel-aligned.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@


# Other crackers

cracker-loaded-p-no-penalties: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) variant-bcrypt-loaded-p-no-penalties.o $(OBJS_LOADED_P)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-openbsd-O0: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) $(CORE)bcrypt-openbsd.c $(TEST)openbsd.c
	$(CC) $(CFLAGS) $(INC_PARAMS) -O0 $^ -o $(BUILD)$@

cracker-openbsd-O1: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) $(CORE)bcrypt-openbsd.c $(TEST)openbsd.c
	$(CC) $(CFLAGS) $(INC_PARAMS) -O1 $^ -o $(BUILD)$@

cracker-openbsd-O2: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) $(CORE)bcrypt-openbsd.c $(TEST)openbsd.c
	$(CC) $(CFLAGS) $(INC_PARAMS) -O2 $^ -o $(BUILD)$@

cracker-openbsd-O3: $(CRACKER)cracker.c $(SOURCES) $(CRACKER_SOURCES) $(CORE)bcrypt-openbsd.c $(TEST)openbsd.c
	$(CC) $(CFLAGS) $(INC_PARAMS) -O3 $^ -o $(BUILD)$@

cracker-parallel-no-vpermq: $(CRACKER)cracker-parallel.c $(SOURCES_PARALLEL) $(CRACKER_SOURCES) variant-bcrypt-parallel-no-vpermq.o $(OBJS_PARALLEL_NO_VPERMQ)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

cracker-parallel-double: $(CRACKER)cracker-parallel-double.c $(SOURCES_PARALLEL_DOUBLE) $(CRACKER_SOURCES) variant-bcrypt-parallel-double.o $(OBJS_PARALLEL_DOUBLE)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@


# Utilities and tests

encrypt: $(CORE)encrypt.c $(SOURCES_NO_CRACKER) $(OBJS)
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

test-parallel-no-vpermq: $(TEST)parallel.c $(TEST_SOURCES) variant-bcrypt-parallel-no-vpermq.o $(OBJS) $(OBJS_PARALLEL_NO_VPERMQ) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-parallel-no-vpermq

test-parallel-double: $(TEST)parallel-double.c $(TEST_SOURCES) variant-bcrypt-parallel-double.o $(OBJS) $(OBJS_PARALLEL_DOUBLE) $(OBJS_TESTING)
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@
	./build/test-parallel-double

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


# No vpermq parallel object code

bcrypt-parallel-no-vpermq.o: $(CORE)bcrypt-parallel-no-vpermq.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-parallel-no-vpermq.o: $(CORE)variant/variant-bcrypt-parallel-no-vpermq.asm build
	$(NASM) $(NASMFLAGS) $< -o $@


# Double parallel object code

bcrypt-parallel-double.o: $(CORE)bcrypt-parallel-double.asm build
	$(NASM) $(NASMFLAGS) $< -o $@

variant-bcrypt-parallel-double.o: $(CORE)variant/variant-bcrypt-parallel-double.asm build
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

parallel-double-test-wrappers.o: $(TEST)parallel-double-test-wrappers.asm build
	$(NASM) $(NASMFLAGS) $< -o $@


# Benchmarks

benchmark: $(BENCHMARK)benchmark.c instructions.o
	$(CC) $(CFLAGS) $(INC_PARAMS) $^ -o $(BUILD)$@

instructions.o: $(BENCHMARK)instructions.asm build
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
