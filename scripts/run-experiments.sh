#!/usr/bin/sh

# pbcrypt: parallel bcrypt for password cracking
# Copyright (C) 2019  Catalina Juarros (catalinajuarros@protonmail.com)

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

PASSWORD="Go Landcrabs!"
SALT="Better Call Salt"
CRACKERS=("cracker" "cracker-no-unrolling" "cracker-loaded-p" "cracker-parallel")
CRACKERS_ALIGNED=("cracker-aligned" "cracker-no-unrolling-aligned" "cracker-loaded-p-aligned" "cracker-parallel-aligned")

# $1: password byte length
generate_password() {
    cd scripts
    python -c "from password import generate_password; print(generate_password('${PASSWORD}', $1))"
    cd ..
}

# $1: password byte length
# $2: encryption rounds log
generate_record() {
    NEW_PASSWORD=`generate_password $1`
    echo `./build/encrypt "$NEW_PASSWORD" "$SALT" $2`
}

# $1: record
# $2: wordlist filename
# $3: batch size
# $4: cracker array
crack_all() {
    declare -a crackers=("${!4}")
    for k in "${crackers[@]}"
    do
        ./build/$k "$1" "$2" $3
    done
}

# $1: password byte length
# $2: encryption rounds log
# $3: batch size
experiment_growing_wordlist() {
    for j in {32..8192..32}
    do
        RECORD=`generate_record $1 $2`
        WORDLIST="./experiments/test-cases/wordlist-$1bytes-${j}passwords"
        crack_all $RECORD $WORDLIST $3 CRACKERS[@]
    done
}

# $1: password byte length
# $2: wordlist length
# $3: batch size
experiment_rounds() {
    for j in {4..16}
    do
        RECORD=`generate_record $1 $j`
        WORDLIST="./experiments/test-cases/wordlist-$1bytes-$2passwords"
        crack_all $RECORD $WORDLIST $3 CRACKERS[@]
    done
}

# $1: wordlist size in bytes
# $2: encryption rounds log
# $3: batch size
experiment_growing_password() {
    for i in {6..72..6}
    do
        local passwords=$(($1 / $i))
        local length=$(($i - 1))
        RECORD=`generate_record ${length} $2`
        WORDLIST="./experiments/test-cases/wordlist-${length}bytes-${passwords}passwords"
        crack_all $RECORD $WORDLIST $3 CRACKERS[@]
    done
}

# $1: wordlist size in bytes
# $2: password list length (must be a multiple of 64)
# $3: encryption rounds log
experiment_growing_batch() {
    RECORD=`generate_record $1 $3`
    WORDLIST="./experiments/test-cases/wordlist-$1bytes-$2passwords"
    echo $WORDLIST
    
    for i in $(eval echo {64..$2..64})
    do
        crack_all $RECORD $WORDLIST $i CRACKERS[@]
    done
}

# $1: password byte length
# $2: encryption rounds log
# $3: batch size
experiment_growing_wordlist_aligned() {
    for j in {128..8192..128}
    do
        RECORD=`generate_record $1 $2`
        WORDLIST="./experiments/test-cases/wordlist-$1bytes-${j}passwords"
        crack_all $RECORD $WORDLIST $3 CRACKERS_ALIGNED[@]
    done
}

# $1: password byte length
# $2: batch size
# $3: record
experiment_no_penalties() {
    for j in {32..8192..32}
    do
        WORDLIST="./experiments/test-cases/wordlist-$1bytes-${j}passwords"
        ./build/cracker $3 $WORDLIST $2
        ./build/cracker-loaded-p $3 $WORDLIST $2
        ./build/cracker-loaded-p-no-penalties $3 $WORDLIST $2
    done
}

# $1: password byte length
# $2: batch size
# $3: record
# $4: optimisation level (0, 1, 2 or 3)
experiment_openbsd() {
    for j in {32..2048..32}
    do
        WORDLIST="./experiments/test-cases/wordlist-$1bytes-${j}passwords"
        ./build/cracker-openbsd-O$4 $3 $WORDLIST $2
        ./build/cracker $3 $WORDLIST $2
    done
}


# Create executables

for k in "${CRACKERS[@]}"
do
    make "$k"
done

for k in "${CRACKERS_ALIGNED[@]}"
do
    make "$k"
done

make cracker-loaded-p-no-penalties

for i in {0..3}
do
    make "cracker-openbsd-O${i}"
done

make cracker-parallel-no-vpermq
make cracker-parallel-double

make encrypt

make benchmark

rm -f *.o


# Run experiments

if [ ! -d ./experiments/measurements ]
then
    mkdir ./experiments/measurements
fi

# Growing wordlist

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-8rounds.csv"

experiment_growing_wordlist 72 8 16
experiment_growing_wordlist 13 8 16
experiment_growing_wordlist 3 8 16

# Rounds

export RESULTS_FILENAME="./experiments/measurements/growing-rounds-13-1024.csv"

experiment_rounds 13 1024 16

# Growing batch

export RESULTS_FILENAME="./experiments/measurements/growing-batch-13-8192.csv"

experiment_growing_batch 13 8192 8

# Aligned code

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-aligned-8rounds.csv"

experiment_growing_wordlist_aligned 13 8 16

# No AVX-SSE penalties

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-no-penalties-8rounds.csv"

RECORD=`generate_record 72 8`
experiment_no_penalties 72 16 $RECORD

RECORD=`generate_record 13 8`
experiment_no_penalties 13 16 $RECORD

RECORD=`generate_record 3 8`
experiment_no_penalties 3 16 $RECORD

# Instruction benchmark

export RESULTS_FILENAME="./experiments/measurements/instruction-benchmark.csv"

./build/benchmark "$RESULTS_FILENAME"

# OpenBSD crackers

for i in {0..3}
do
    export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-openbsd-O${i}.csv"
    RECORD=`generate_record 13 8`
    experiment_openbsd 13 16 $RECORD $i
done

# Parallel cracker for comparison with OpenBSD crackers

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-parallel.csv"

RECORD=`generate_record 13 8`

for j in {32..2048..32}
do
    WORDLIST="./experiments/test-cases/wordlist-13bytes-${j}passwords"
    ./build/cracker-parallel $RECORD $WORDLIST 16
done

# Parallel cracker without expensive vpermq instruction

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-parallel-no-vpermq.csv"

RECORD=`generate_record 13 8`

for j in {32..8192..32}
do
    WORDLIST="./experiments/test-cases/wordlist-13bytes-${j}passwords"
    ./build/cracker-parallel-no-vpermq $RECORD $WORDLIST 16
done

# Parallel cracker without expensive vpermq instruction

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-parallel-no-vpermq.csv"

RECORD=`generate_record 13 8`

for j in {32..8192..32}
do
    WORDLIST="./experiments/test-cases/wordlist-13bytes-${j}passwords"
    ./build/cracker-parallel-no-vpermq $RECORD $WORDLIST 16
done

# Double parallel cracker

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-parallel-double.csv"

RECORD=`generate_record 13 8`

for j in {32..8192..32}
do
    WORDLIST="./experiments/test-cases/wordlist-13bytes-${j}passwords"
    ./build/cracker-parallel-double $RECORD $WORDLIST 16
done

export RESULTS_FILENAME="./experiments/measurements/growing-rounds-parallel-double.csv"

for j in {4..16}
do
    RECORD=`generate_record 13 $j`
    WORDLIST="./experiments/test-cases/wordlist-13bytes-1024passwords"
    ./build/cracker-parallel-double $RECORD $WORDLIST 16
done