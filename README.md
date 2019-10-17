# pbcrypt

Final project for my Computer Organisation II course, MSc Computer Science,
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
- Linux kernel
- Python 3 (exclusively for generating test cases)

## How to build

### Cracker

```$ make cracker```

will create the executable `./build/cracker`. For the version without loop unrolling,
replace `cracker` with `cracker-no-unrolling`. For the parallel version, replace it
with `cracker-parallel`.

### Tests

```$ make test```

will test ASM macros and bcrypt components against their counterparts from
the OpenBSD source code.

To test other variants, replace `test` with `test-no-unrolling`,
`test-loaded-p` or `test-parallel`.

## How to run

### Cracker

```$ ./build/cracker <PASSWORD_RECORD> <PATH_TO_WORDLIST> <PASSWORDS_PER_BATCH>```

where `<PATH_TO_WORDLIST>` is the **absolute path** to a list of **newline-separated
plaintext passwords** of the **same length**. The **first line** should be
the **length of the passwords** in base 10.
The optional argument `<PASSWORDS_PER_BATCH>` is the number of passwords read
into each batch for hashing and it defaults to 1024. For experiment design reasons,
the batch size must be a multiple of 4.

#### Example:

```$ ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV ./my_wordlist```

### Test case generation

Unfortunately, I downloaded my wordlist from a site whose CDN is now broken.
I'll put it up on Mega or something as soon as I have the time but you'll
have to do without the original wordlist for a bit. Sorry!

```$ python3 ./scripts/split-wordlist.py```

will split the wordlist into many different files that satisfy the cracker's
preconditions: all passwords are the same length in bytes and said length is
the first line in the file.

```$ ./scripts/generate-test-cases.sh```

will use the files created by the previous command to generate wordlists
of increasing size and password byte length.

### Experiments

```$ ./scripts/run-experiments.sh```

will run all experiments: measure all four crackers' performance at cracking
with increasingly large wordlists, cracking hashes with an increasing number
of encryption rounds, cracking passwords of different lengths with wordlists
of the same size in bytes and cracking a password with the same wordlist and
varying batch sizes; measure performance improvements when aligning code to
cache line size and removing AVX-SSE transitions; measure execution time for
different instructions; compare performance against that of OpenBSD code with
varying levels of optimisation.
