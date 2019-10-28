# pbcrypt

Final project for my Computer Organisation II course, MSc Computer Science,
University of Buenos Aires (UBA).

This is basically research into different methods for optimising a
**brute-force password cracker for bcrypt** with Intel's AVX2 extensions,
such as storing frequently used data in YMM registers and hashing
several passwords at once with SIMD instructions after rearranging
the bytes from all plaintexts.

Latest release: [v0.1](https://github.com/cat-j/pbcrypt/releases/tag/first-alpha)

## Details

Currently limited in scope to bcrypt version `$2b$`. More versions
might be supported later.

All commands in the next two sections must be executed from the repository's
base directory.

### Requirements

- 64-bit Intel processor with AVX2 capabilities
- Linux kernel
- Python 3 (exclusively for generating test cases)
- GCC

## How to build

### Cracker

```$ make cracker```

will create the executable `./build/cracker`.
- For the variant without loop unrolling, replace `cracker` with
  `cracker-no-unrolling`.
- For the variant with pre-loaded salt and P-array, replace it
  with `cracker-loaded-p`.
- For the parallel variant, replace it with `cracker-parallel`.
- For the double parallel variant (8 passwords), replace it
  with `cracker-parallel-double`.
- For cache-aligned variants, add `-aligned` to executable name:
  `cracker-aligned`, `cracker-no-unrolling-aligned`, etc.
  This doesn't work with the double parallel variant.
- For the loaded P-array variant with no AVX-SSE transition,
  use `cracker-loaded-p-no-penalties`.

### Tests

```$ make test```

will test ASM macros and bcrypt components against their counterparts from
the OpenBSD source code.

To test other variants, replace `test` with `test-no-unrolling`,
`test-loaded-p`, `test-parallel` or `test-loaded-p-no-penalties`.

## How to run

### Cracker

```$ ./build/cracker <PASSWORD_RECORD> <PATH_TO_WORDLIST> <PASSWORDS_PER_BATCH>```

where `<PATH_TO_WORDLIST>` is the **absolute path** to a list of **newline-separated
plaintext passwords** of the **same length**. The **first line** should be
the **length of the passwords** in base 10.
The optional argument `<PASSWORDS_PER_BATCH>` is the number of passwords read
into each batch for hashing and it defaults to 1024. If using `cracker-parallel`,
`<PASSWORDS_PER_BATCH` must be a multiple of 4, and if using `cracker-parallel-double`,
it must be a multiple of 8.

#### Example:

```$ ./build/cracker \$2b\$08\$Z1/fWkjsYUDNSCDAQS3HOO.jYkAT2lI6RZco8UP86hp5oqS7.kZJV ./my_wordlist```

### Test case generation

First, download the wordlist from [here](https://mega.nz/#!dNYCUSiI!5RkPoiP80Ej_IE4AUXhcQ_bWSCdP--YuVUcRjMv8l9E)
and extract it into a folder called `wordlists/`.

```$ python3 ./scripts/split-wordlist.py ./wordlists/realhuman-phill.txt```

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
