# simd-crypto

Final project for Computer Organisation II course, MSc Computer Science,
University of Buenos Aires (UBA).

This is basically research into whether a *brute-force password cracker for bcrypt*
can be optimised by rearranging the bytes from all plaintexts so that hashing
is done with SIMD for several passwords at once.

## Details

Currently limited in scope to bcrypt version `$2b$`. More versions
will be supported later.

All commands in the next two sections must be executed from the repository's
base directory.

### Requirements

- 64-bit Intel processor
- Unix-like operating system

## How to build

### Cracker

```$ make cracker```

will create the executable `./build/cracker`. For the version without loop unrolling,
replace `cracker` with `cracker-no-unrolling`.

### Tests

```$ make test```

will test ASM macros and bcrypt components against their counterparts from
the OpenBSD source code.

## How to run

```$ ./build/cracker <PASSWORD_RECORD> <PATH_TO_WORDLIST> <PASSWORDS_PER_BATCH>```

where `<PATH_TO_WORDLIST>` is the **absolute path** to a list of **newline-separated
plaintext passwords** of the **same length**. The **first line** should be
the **length of the passwords** in base 10.
The optional argument `<PASSWORDS_PER_BATCH>` is the number of passwords read
into each batch for hashing and it defaults to 1024.

### Example:

```$ ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV ./my_wordlist```