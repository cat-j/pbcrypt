; C functions
extern malloc
extern free

global blowfish_encrypt

section .data

; 18 32-bit constants P_n (0 <= n < 18) derived from the hexadecimal digits of pi,
; later to be encrypted with a secret key
; split into three tags for readability, but only P_ARRAY is used
P_ARRAY:   dd 0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0
P_ARRAY_1: dd 0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c
P_ARRAY_2: dd 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b

; how many 1-byte memory slots each P_n takes up
%define P_VALUE_MEMORY_SIZE 4
; number of elements in P-array
%define P_ARRAY_LENGTH 18

section .text

; uint8_t* blowfish_encrypt(uint8_t* plaintext,
;                           uint32_t plaintext_length,
;                           uint8_t* key,
;                           uint32_t key_length)

blowfish_encrypt:
    ; rdi: pointer to plaintext string
    ; rsi: string length
    ; rdx: pointer to key
    ; rcx: key length (in bits)
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r12
        push r13
        push r14

    .allocate_for_subkeys:
        ; keep values in untouchable registers!
        mov rbx, rdi
        mov r12, rsi
        mov r13, rdx
        mov r14, rcx
        ; allocate space (address returned in rax)
        mov rdi, P_ARRAY_LENGTH * P_VALUE_MEMORY_SIZE
        call malloc
    
    .initialise_for_key_schedule:
        ; key pointer is already in r13
        ; key length is already in r14
        ; subkey pointer, i.e. target pointer, is already in rax
        xor rdx, rdx ; clean for encryption
        xor rdi, rdi ; clean for encryption
        xor r8, r8 ; initialise P index
        xor r15, r15 ; initialise key index
        mov rsi, P_ARRAY
        shr r14, 5 ; divide by 32 since we're counting 32-bit chunks
        mov rcx, r14 ; initialise key counter
        mov r9, P_ARRAY_LENGTH ; initialise P counter

    .compute_subkeys:
        %define key edx
        %define pvalue edi
        %define pptr rsi
        %define keyptr r13
        %define targetptr rax
        %define keycounter rcx
        %define keyidx r15
        %define pidx r8
        %define pcounter r9
        %define keylength r14
        ; TODO: compare performance with reading two elements at a time (64 bit regs)
        ; p displacement == target displacement
        mov key, [keyptr + keyidx * P_VALUE_MEMORY_SIZE]
        mov pvalue, [pptr + pidx * P_VALUE_MEMORY_SIZE]
        xor pvalue, key ; encrypt
        mov [targetptr + pidx], pvalue ; write subkey index
        dec keycounter
        jz  .reset_key_counter ; do modulus without really doing modulus
        inc keyidx ; advance indices
        
        .compute_subkeys_advance:
        inc pidx
        dec pcounter
        jnz .compute_subkeys ; another loop iteration
        jmp .end ; TODO: replace this with whatever should ACTUALLY BE DONE afterwards!
        
        .reset_key_counter:
        mov keycounter, keylength
        xor keyidx, keyidx
        jmp .compute_subkeys_advance
    
    .end:
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret