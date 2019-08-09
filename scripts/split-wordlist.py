from argparse import ArgumentParser
from os import path

def get_sub_wordlist(filename, line_size):
    sub_wl_name = "{}-{}".format(filename, line_size)
    if not path.isfile(sub_wl_name):
        file = open(sub_wl_name, "a")
        file.write("{}\n".format(line_size))
        return file
    else:
        file = open(sub_wl_name, "a")
        return file

# Split a single wordlist into many files,
# each of which only has plaintext passwords
# of a single length in bytes.
def split_wordlist(filename):
    with open(filename) as f:
        for line in f:
            line_size = len(line.rstrip('\n').encode('utf-8'))
            sub_wordlist = get_sub_wordlist(filename, line_size)
            sub_wordlist.write(line)
            sub_wordlist.close()
    return

# Get command line arguments
def get_args():
    parser = ArgumentParser()
    parser.add_argument("filename", help="Path to wordlist file")
    args = parser.parse_args()
    return args.filename

def main():
    filename = get_args()
    split_wordlist(filename)
    return

main()