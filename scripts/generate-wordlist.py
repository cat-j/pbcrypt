# pbcrypt: parallel bcrypt for password cracking
# Copyright (C) 2019  Catalina Juarros <https://github.com/cat-j>

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

from argparse import ArgumentParser
from password import generate_password

src_dir = "./wordlists/"
dst_dir = "./experiments/test-cases/"

# Create a filler password for generating bigger files
# if there's not enough data in the source.
def generate_filler(password, pass_length):
    filler = chr( ord(password[0]) + 1 ) + password[1:]
    return generate_password(filler, pass_length)

# Create a wordlist where the last plaintext
# is a `pass_length` bytes long mutation of `password`
# and the total number of plaintexts is `n_passwords`.
def generate_wordlist(password, pass_length, n_passwords):
    src_filename = "{}realhuman_phill.txt-{}".format(src_dir, pass_length)
    dst_filename = "{}wordlist-{}bytes-{}passwords" \
        .format(dst_dir, pass_length, n_passwords)

    filler = generate_filler(password, pass_length)

    with open(src_filename) as src_f:
        dst_f = open(dst_filename, "w")
        line = src_f.readline()
        dst_f.write(line)

        for i in range(n_passwords-1):
            line = src_f.readline()
            dst_f.write(line)
            if not line:
                dst_f.write("{}\n".format(filler))
        
        dst_f.write("{}\n".format(generate_password(password, pass_length)))
        dst_f.close()

    return

# Get command line arguments
def get_args():
    parser = ArgumentParser()
    parser.add_argument("password", help="Password to generate new one from")
    parser.add_argument("length", help="Desired password length", type=int)
    parser.add_argument("n_passwords", help="Number of passwords in destination file", type=int)
    args = parser.parse_args()
    return (args.password, args.length, args.n_passwords)

def main():
    (password, length, n_passwords) = get_args()
    if (length < 1 or n_passwords < 1):
        raise ValueError("Length and number of passwords must be positive integers.")
    generate_wordlist(password, length, n_passwords)
    return

main()