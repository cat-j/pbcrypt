from argparse import ArgumentParser

# Given a password, mutate it into another one
# of a certain length by wrapping around its characters.
def generate_password(password, length):
    n = len(password)
    return password*(length//n) + password[:length%n]

# Create a wordlist where the last plaintext
# is a `pass_length` bytes long mutation of `password`
# and the total number of plaintexts is `n_passwords`.
def generate_wordlist(password, pass_length, n_passwords):
    src_filename = "./wordlists/realhuman_phill.txt-{}".format(pass_length)
    dst_filename = "./experiments/test-cases/wordlist-{}bytes-{}passwords" \
        .format(pass_length, n_passwords)

    with open(src_filename) as src_f:
        dst_f = open(dst_filename, "a")
        line = src_f.readline()
        dst_f.write(line)

        for i in range(n_passwords-1):
            line = src_f.readline()
            dst_f.write(line)
        
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