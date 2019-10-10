#!/usr/bin/sh

PASSWORD="Go Landcrabs!"

varying_length() {
    local length=$1
    for i in {32..8192..32}
    do
        python ./scripts/generate-wordlist.py "$PASSWORD" $length $i
    done
}

generate_varying_length() {
    varying_length 3
    varying_length 13
    varying_length 72
}

if [ ! -d ./experiments/test-cases/ ]
then
    echo "Creating test case directory..."
    mkdir ./experiments/test-cases
fi

generate_varying_length