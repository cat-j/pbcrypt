*IMPORTANT: DES is a BAD and OBSOLETE encryption algorithm and the initial key
permutation is just needlessly complicated for something that's not even useful
anymore. I'm gonna go straight to Blowfish and add another algorithm if needed
because the 58-bit key is just pointlessly contrived.*

# DES

It is a block cipher, meaning it ALWAYS operates on complete blocks of data

- Fixed block size (64 bits)
- Blocks are divided into 32-bit L and R sub-blocks

DES's convoluted history, rife with suspicions about an NSA backdoor, could actually
make a good case *for* implementing it -- getting familiar with the specific features
that made it suspicious/vulnerable could be a learning opportunity

## Parameters

- Pointer to string
- String length
- 56 bit key (actually 64 but 8 of those are just for parity checking; every 8th bit
  is ignored)

## Sizes

- PC tables: 56 numbers between 0 and 63, i.e. 56 bytes, i.e. 448 bits

## General operations

- Permute the key with a mask (PSHUFB or similar - the PC-1 table is fixed.
  Shuffle bits!)
  - PC-1 is 56 bytes, so it would require at least 4 XMM registers, which means
    this takes several operations!
  - Maybe it's better to operate in a general purpose register, since there are
    no AVX instructions for single-bit manipulation
    - PEXT in 64 bits: 
- Divide the resulting key into two 28-bit halves, probably with shifts or masks
- Loop to create 16 block pairs by shifting the previous block by the corresponding
  amount of bits. Permute each of these block pairs with PC-2. These are K1-K16.
  This might require copying blocks to memory... or maybe YMM/ZMM
  registers can help, probably the latter is the best option. It's probably a good
  idea to keep each pair in the same register WAIT I DON'T HAVE ENOUGH REGS.
- For each 64-bit block of the plaintext message:
  - Shuffle bits according to initial permutation
  - Divide permuted block into two 32-bit halves L0 and R0
  - For 16 rounds, calculate Ln and Rn with masks/shifts, XORs and f(Rn-1, Kn)
    - First step of the f calculation: selection table E, probably a bit shuffle
    - XOR it with the corresponding key
    - Replace each resulting 6-bit block with a 4-bit block