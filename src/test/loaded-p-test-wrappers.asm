; Many functions from the loaded P implementation of bcrypt
; require some YMM registers to remain unchanged between calls,
; and calling them from C often breaks this.
; These wrappers are intended for testing the loaded P functions
; without using inline ASM or pushing YMM registers.

; Functions to be wrapped
extern blowfish_init_state_asm
extern blowfish_expand_state_asm
extern blowfish_expand_0_state_asm
extern blowfish_expand_0_state_salt_asm

; Exported functions
global blowfish_expand_state_wrapper


section .data

; how many 1-byte memory slots each P_n takes up
%define P_VALUE_MEMORY_SIZE 4
; how many 1-byte memory slots each element in an S-box takes up
%define S_ELEMENT_MEMORY_SIZE 4
; how many 1-byte memory slots one S-box takes up
%define S_BOX_MEMORY_SIZE 1024
; encryption rounds
%define ROUNDS 16
; YMM register size in bytes
%define YMM_SIZE 32
; P-array byte offset within context struct
%define BLF_CTX_P_OFFSET 4096
; length of bcrypt hash in 32-bit words
%define BCRYPT_WORDS 6

align 16
endianness_mask: db \
0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, \
0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c, \
0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14, \
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c


section .text

; TODO: move all macros to a single file
%define salt                xmm0
%define p_0_7               ymm1
%define p_0_7x              xmm1
%define p_8_15              ymm2
%define p_8_15x             xmm2
%define p_16_17             xmm3
%define endianness_mask_ymm ymm15
%define endianness_mask_xmm xmm15

; Keep salt and P-array cached
; %1 -> state
; %2 -> salt
%macro LOAD_SALT_AND_P 2
    vmovdqa  endianness_mask_ymm, [endianness_mask]
    vpxor    p_16_17, p_16_17
    
    movdqu   salt, [%2]
    vmovdqa  p_0_7, [%1 + BLF_CTX_P_OFFSET]
    vmovdqa  p_8_15, [%1 + BLF_CTX_P_OFFSET + 8*P_VALUE_MEMORY_SIZE]
    vpinsrq  p_16_17, p_16_17, \
             [%1 + BLF_CTX_P_OFFSET + 16*P_VALUE_MEMORY_SIZE], 0
    
    vpshufb  p_0_7, endianness_mask_ymm
    vpshufb  p_8_15, endianness_mask_ymm
    vpshufb  ymm3, endianness_mask_ymm
%endmacro

blowfish_expand_state_wrapper:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> 4 to 56 byte key
    ; rcx:   key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_function:
        call blowfish_init_state_asm
        LOAD_SALT_AND_P rdi, rsi
        call blowfish_expand_state_asm

    .end:
        pop rbp
        ret

blowfish_expand_0_state_wrapper:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> 4 to 56 byte key
    ; rcx:   key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        sub  rbp, 8

    .do_function:
        ; Save these values because blowfish_expand_state_asm would modify them
        ; rbx -> salt
        ; r12 -> key
        ; r14:   key length in bytes
        mov rbx, rsi
        mov r12, rdx
        mov r14, rcx
        
        call blowfish_init_state_asm
        LOAD_SALT_AND_P rdi, rbx
        call blowfish_expand_state_asm

        %define salt_ptr  rbx
        %define key_ptr   r12
        %define key_len   r14

        mov  rsi, key_ptr
        mov  rdx, key_len
        call blowfish_expand_0_state_asm

    .end:
        add rbp, 8
        pop rbx
        pop rbp
        ret