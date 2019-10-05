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
    for i in {3..12}
    do
        varying_length $i
    done

    for i in {13..65..13}
    do
        varying_length $i
    done

    varying_length 72
}

generate_varying_length

