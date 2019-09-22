# simd-crypto

Final project for Computer Organisation II course, MSc Computer Science,
University of Buenos Aires (UBA).

This is basically research into different methods for optimising a
**brute-force password cracker for bcrypt** with Intel's AVX2 extensions,
such as storing frequently used data in YMM registers and hashing
several passwords at once with SIMD instructions after rearranging
the bytes from all plaintexts. 

## Details

Currently limited in scope to bcrypt version `$2b$`. More versions
will be supported later.

All commands in the next two sections must be executed from the repository's
base directory.

### Requirements

- 64-bit Intel processor with AVX2 capabilities
- Unix-like operating system

## How to build

### Cracker

```$ make cracker```

will create the executable `./build/cracker`. For the version without loop unrolling,
replace `cracker` with `cracker-no-unrolling`. Parallel cracking is still under development.

### Tests

```$ make test```

will test ASM macros and bcrypt components against their counterparts from
the OpenBSD source code.

To test other variants, replace `test` with `test-no-unrolling`,
`test-loaded-p` or `test-parallel` (the last one is still under development).

## How to run

```$ ./build/cracker <PASSWORD_RECORD> <PATH_TO_WORDLIST> <PASSWORDS_PER_BATCH>```

where `<PATH_TO_WORDLIST>` is the **absolute path** to a list of **newline-separated
plaintext passwords** of the **same length**. The **first line** should be
the **length of the passwords** in base 10.
The optional argument `<PASSWORDS_PER_BATCH>` is the number of passwords read
into each batch for hashing and it defaults to 1024.

### Example:

```$ ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV ./my_wordlist```
