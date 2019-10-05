#!/usr/bin/sh

PASSWORD="Go Landcrabs!"

varying_length() {
    local length=$1
    for i in {16..65536..16}
    do
        python ./scripts/generate-wordlist.py "$PASSWORD" $length $i
    done
}

generate_varying_length() {
    for i in {3..20}
    do
        varying_length $i
    done

    for i in {25..70..5}
    do
        varying_length $i
    done

    varying_length 72
}

if [ ! -d ./experiments/test-cases ]
then
    mkdir ./experiments/test-cases
fi

generate_varying_length

