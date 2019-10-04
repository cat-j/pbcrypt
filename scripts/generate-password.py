from argparse import ArgumentParser

def generate_password(password, length):
    n = len(password)
    return password*(length//n) + password[:length%n]

# Get command line arguments
def get_args():
    parser = ArgumentParser()
    parser.add_argument("password", help="Password to generate new one from")
    parser.add_argument("length", help="Desired password length", type=int)
    args = parser.parse_args()
    return (args.password, args.length)

def main():
    (password, length) = get_args()
    print(generate_password(password, length))
    return

main()