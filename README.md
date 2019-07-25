# simd-crypto

Final project for Computer Organisation II course, MSc Computer Science,
University of Buenos Aires (UBA).

This is basically research into whether a *brute-force password cracker for bcrypt*
can be optimised by rearranging the bytes from all plaintexts so that hashing
is done with SIMD for several passwords at once.

## Details

Limited in scope to bcrypt version `$2b`.

## How to build

### Tests

```make test```

will test ASM macros and bcrypt components against their counterparts from
the OpenBSD source code.