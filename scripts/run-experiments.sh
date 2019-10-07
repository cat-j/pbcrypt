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
# $2: number of passwords in wordlist
get_wordlist_filename() {
    local wordlist="./experiments/test-cases/wordlist-$1bytes-$2passwords"
    echo $wordlist
}

# $1: password byte length
# $2: number of passwords in wordlist
# $3: encryption rounds log
# $4: batch size
encrypt_and_crack() {
    NEW_PASSWORD=`generate_password $1`
    RECORD=`./build/encrypt "$NEW_PASSWORD" "$SALT" $3`
    WORDLIST=`get_wordlist_filename $1 $2`

    for k in "${CRACKERS[@]}"
    do
        echo "====== Cracker: $k, wordlist length: $2, batch size: $4 ======"
        ./build/$k "$RECORD" "$WORDLIST" $4
    done
}


# Create executables

for i in "${CRACKERS[@]}"
do
    make "$i"
done

make encrypt


# Run experiments

if [ ! -d ./experiments/measurements ]
then
    mkdir ./experiments/measurements
fi

export RESULTS_FILENAME="./experiments/measurements/pepe.csv"

for i in {3..20}
do
    for j in {16..65536..16}
    do
        encrypt_and_crack $i $j 8 16
    done
done

for i in {25..70..5}
do
    for j in {16..65536..16}
    do
        encrypt_and_crack $i $j 8 16
    done
done

for j in {16..65536..16}
do
    encrypt_and_crack 72 $j 8 16
done