#!/usr/bin/sh

PASSWORD="Go Landcrabs!"
SALT="Better Call Salt"
CRACKERS=(cracker cracker-no-unrolling cracker-loaded-p cracker-parallel)

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
crack_all() {
    for k in "${CRACKERS[@]}"
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
        crack_all $RECORD $WORDLIST $3
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
        crack_all $RECORD $WORDLIST $3
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
        crack_all $RECORD $WORDLIST $3
    done
}

# $1: wordlist size in bytes
# $2: password list length (must be a multiple of 4)
# $3: encryption rounds log
experiment_growing_batch() {
    RECORD=`generate_record $1 $3`
    WORDLIST="./experiments/test-cases/wordlist-$1bytes-$2passwords"
    echo $WORDLIST
    
    for i in $(eval echo {4..$2..4})
    do
        crack_all $RECORD $WORDLIST $i
    done
}

# Create executables

for k in "${CRACKERS[@]}"
do
    make "$k"
done

make encrypt


# Run experiments

if [ ! -d ./experiments/measurements ]
then
    mkdir ./experiments/measurements
fi


export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-8rounds.csv"

experiment_growing_wordlist 72 8 16
experiment_growing_wordlist 13 8 16
experiment_growing_wordlist 3 8 16


export RESULTS_FILENAME="./experiments/measurements/growing-rounds-13-1024.csv"

experiment_rounds 13 1024 16


export RESULTS_FILENAME="./experiments/measurements/growing-password-2mb.csv"

WL_BYTES=$((5*7*11*72*2))
experiment_growing_password $WL_BYTES 8 16


export RESULTS_FILENAME="./experiments/measurements/growing-batch-13-16384.csv"

experiment_growing_batch 13 16384 8