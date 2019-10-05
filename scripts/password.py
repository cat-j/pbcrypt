# Given a password, mutate it into another one
# of a certain length by wrapping around its characters.
def generate_password(password, length):
    n = len(password)
    return password*(length//n) + password[:length%n]