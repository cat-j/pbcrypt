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
        WORDLIST="./experiments/test-cases/wordlist-13bytes-${j}passwords"
        crack_all $RECORD $WORDLIST $3
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

export RESULTS_FILENAME="./experiments/measurements/growing-wordlist-8roundsTEST2.csv"

experiment_growing_wordlist 13 8 16