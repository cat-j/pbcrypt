#!/usr/bin/sh

PASSWORD="Go Landcrabs!"

cd scripts

generate_password() {
    python -c "from password import generate_password; print(generate_password('${PASSWORD}', $1))"
}

for i in {3..20}
do
    current_password=`generate_password $i`
    echo $current_password
done

for i in {25..70..5}
do
    current_password=`generate_password $i`
    echo $current_password
done

current_password=`generate_password 72`
echo $current_password

cd ..