#!/usr/bin/sh

PASSWORD="Go Landcrabs!"

for i in {4..65540..4}
do
    python ./scripts/generate-wordlist.py "$PASSWORD" 13 $i
done
