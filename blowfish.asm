global blowfish_encrypt

section .data

; 18 32-bit constants P_n (0 <= n < 18) derived from the hexadecimal digits of pi,
; later to be encrypted with a secret key
P_ARRAY: dd 0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
            0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
            0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b

; how many 1-byte memory slots each P_n takes up
%define P_MEMORY_SIZE 4

section .text

blowfish_encrypt:
    ; rdi: pointer to plaintext string
    ; rsi: string length
    ; rdx: pointer to key
    ; rcx: key length
    ; r8:  pointer to subkey array (overwrite)
    .build_frame:
        push rbp
        mov  rbp, rsp

    .compute_subkeys:
        ; TODO: compare performance with reading two elements at a time (64 bit regs)
        ; p displacement == target displacement
        mov key, [keyptr + keyidx * P_MEMORY_SIZE]
        mov pvalue, [pptr + pidx * P_MEMORY_SIZE]
        xor pvalue, key ; encrypt
        mov [targetptr + pidx], pvalue ; write subkey index
        dec keycounter
        jz  .reset_key_counter ; do modulus without really doing modulus
        
        .compute_subkeys_advance:
        inc keyidx ; advance indices
        inc pidx
        dec pcounter
        jnz .compute_subkeys ; another loop iteration
        jmp .end ; TODO: replace this with whatever should ACTUALLY BE DONE afterwards!
        
        .reset_key_counter:
        mov keycounter, keysize
        jmp .compute_subkeys_advance
    
    .end:
        pop rbp
        ret