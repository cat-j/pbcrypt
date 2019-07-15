# simd-crypto

Final project for Computer Organisation II course, MSc Computer Science,
University of Buenos Aires (UBA).

This is basically research into whether a *brute-force password cracker for bcrypt*
can be optimised by rearranging the bytes from all plaintexts so that hashing
is done with SIMD for several passwords at once.