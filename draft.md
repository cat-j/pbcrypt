# DES

It is a block cipher, meaning it ALWAYS operates on complete blocks of data

- Fixed block size (64 bits)
- Blocks are divided into 32-bit L and R sub-blocks

## Parameters:

- Pointer to string
- String length
- 56 bit key (actually 64 but 8 of those are just for parity checking; every 8th bit
  is ignored)

DES's convoluted history, rife with suspicions about an NSA backdoor, could actually
make a good case *for* implementing it -- getting familiar with the specific features
that made it suspicious/vulnerable could be a learning opportunity

## General operations:

- Permute the key with a mask (PSHUFB or similar - the PC-1 table is fixed)
- Divide the resulting key into two 28-bit halves, probably with shifts or masks
