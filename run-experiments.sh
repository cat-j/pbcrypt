#!/usr/bin/sh

PASSWORD="Go Landcrabs!"
SALT="Better Call Saul"

generate_password() {
    cd scripts
    python -c "from password import generate_password; print(generate_password('${PASSWORD}', $1))"
    cd ..
}

get_wordlist_filename() {
    local wordlist="./experiments/test-cases/wordlist-$1bytes-$2passwords"
    echo $wordlist
}

encrypt_and_crack() {
    NEW_PASSWORD=`generate_password $1`
    RECORD=`./build/encrypt "$NEW_PASSWORD" "$SALT" $3`
    WORDLIST=`get_wordlist_filename $1 $2`
    ./build/cracker $RECORD $WORDLIST $3
}

for i in {3..20}
do
    encrypt_and_crack $i 16 8
done

for i in {25..70..5}
do
    encrypt_and_crack $i 16 8
done

encrypt_and_crack 72 16 8