#!/usr/bin/sh

PASSWORD="Go Landcrabs!"

varying_length() {
    local length=$1
    for i in {4..65540..4}
    do
        python ./scripts/generate-wordlist.py "$PASSWORD" $length $i
    done
}

for i in {1..12}
do
    varying_length $i
done

for i in {39, 52, 65}
do
    varying_length $i
done

varying_length 72
