#!/usr/bin/sh

PASSWORD="Go Landcrabs!"

growing_wordlist() {
    local length=$1
    for i in {32..8192..32}
    do
        python ./scripts/generate-wordlist.py "$PASSWORD" $length $i
    done
}

generate_growing_wordlist() {
    growing_wordlist 3
    growing_wordlist 13
    growing_wordlist 72
}

if [ ! -d ./experiments/test-cases/ ]
then
    echo "Creating test case directory..."
    mkdir ./experiments/test-cases
fi

generate_growing_wordlist