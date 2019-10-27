#!/usr/bin/sh

# pbcrypt: parallel bcrypt for password cracking
# Copyright (C) 2019  Catalina Juarros (catalinajuarros@protonmail.com)

# This file is part of pbcrypt.

# pbcrypt is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.

# pbcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.

PASSWORD="Go Landcrabs!"


# Function definitions

# $1: password length
growing_wordlist() {
    local length=$1
    for i in {32..8192..32}
    do
        python ./scripts/generate-wordlist.py "$PASSWORD" $length $i
    done
}

# $1: wordlist size in bytes
growing_password() {
    for i in {6..72..6}
    do
        local passwords=$(($1 / $i))
        python ./scripts/generate-wordlist.py "$PASSWORD" $((i - 1)) $passwords
    done
}

# $1: password length
growing_batch() {
    python ./scripts/generate-wordlist.py "$PASSWORD" $1 16384
}

generate_growing_wordlist() {
    growing_wordlist 3
    growing_wordlist 13
    growing_wordlist 72
}

generate_growing_password() {
    # make sure it's divisible by 6, 12, ... , 72
    WL_SIZE=$((5*7*11*72*2))
    growing_password $WL_SIZE
}

generate_growing_batch() {
    growing_batch 13
}


# Generate test cases

if [ ! -d ./experiments/test-cases/ ]
then
    echo "Creating test case directory..."
    mkdir ./experiments/test-cases
fi

# generate_growing_wordlist

generate_growing_password

generate_growing_batch