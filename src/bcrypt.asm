; C functions
extern malloc
extern free

; variables
extern initstate_asm

global blowfish_init_state_asm
global blowfish_expand_state_asm
; global bcrypt_encrypt

section .data

; how many 1-byte memory slots each P_n takes up
%define P_VALUE_MEMORY_SIZE 4
; number of elements in P-array
; %define P_ARRAY_LENGTH 18
; encryption rounds
%define ROUNDS 16
; YMM register size in bytes
%define YMM_SIZE 32
; P-array byte offset within context struct
%define BLF_CTX_P_OFFSET 4096

%define SALT_BYTES 16

section .text

; Function for Feistel network
; %1 -> S-box
; %2: right half of data block
%macro F 2
%endmacro

; void blowfish_init_state_asm(blf_ctx* state)

blowfish_init_state_asm:
    ; rdi -> blowfish state (modified)
    ; address MUST be 32-bit aligned
    .build_frame:
        push rbp
        mov  rbp, rsp
    
    .copy_S_boxes:
        %assign i 0
        ; 4 256-element boxes => 1024 elements
        ; 4 bytes per element => 4096 bytes total
        ; 32 bytes per YMM register => 4096/32 = 128 accesses to copy all the boxes
        %rep    128
            vmovdqa ymm0, [initstate_asm + i*YMM_SIZE]
            vmovdqa [rdi + i*YMM_SIZE], ymm0
            %assign i i+1
        %endrep

    .copy_P_array:
        ; 18 4-byte elements => 72 bytes
        ; 32 bytes per YMM register => 2 accesses for the first 64
        ; 1 access to 8 remaining bytes
        vmovdqa ymm0, [initstate_asm + BLF_CTX_P_OFFSET]
        vmovdqa [rdi + BLF_CTX_P_OFFSET], ymm0
        vmovdqa ymm0, [initstate_asm + BLF_CTX_P_OFFSET + 32]
        vmovdqa [rdi + BLF_CTX_P_OFFSET + 32], ymm0
        mov     rdx, [initstate_asm + BLF_CTX_P_OFFSET + 64] ; last bytes
        mov     [rdi + BLF_CTX_P_OFFSET + 64], rdx

    .end:
        pop rbp
        ret

; void blowfish_expand_state_asm(blf_ctx* state, const char* salt,
;                                const char* key, uint16_t keybytes)

blowfish_expand_state_asm:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> 4 to 56 byte key
    ; rcx:   key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp
        push r12
        push rbx
    
    %define key_data r9
    %define key_data_lower r9b
    %define ctx_data r10

    %define key_idx r8
    %define p_idx r11

    %define key_ptr rdx
    %define ctx_ptr rdi
    
    %define key_data_ctr r12
    %define key_len rcx

    ; initialise regs
    ; rdi+4096 -> P-array
    ; rdx      -> key
    ; r8:  key index
    ; r9:  8 key bytes
    ; r10: 8 XOR'd P-array bytes
    ; initialise indices and key data at 0
    xor r8, r8
    xor r11, r11
    xor r9, r9 ; because a^0 = a

    .xor_p_array_loop:
        mov ctx_data, [ctx_ptr + BLF_CTX_P_OFFSET + p_idx] ; read two P elements
        xor key_data_ctr, key_data_ctr

        .read_key_data:
            cmp key_idx, key_len
            jl  .continue
            xor key_idx, key_idx ; wrap around key w/o modulus
            .continue:
            shl key_data, 8 ; next byte goes in lowest 8
            mov key_data_lower, [key_ptr + key_idx]
            inc key_idx
            inc key_data_ctr
            cmp key_data_ctr, 8
            jl  .read_key_data
        
        xor ctx_data, key_data
        mov [ctx_ptr + BLF_CTX_P_OFFSET + p_idx], ctx_data
        add p_idx, 2 ; p-array is dword-indexed
        cmp p_idx, 18
        jl  .xor_p_array_loop
    
    .encrypt_p_array:
        %define datal ymm0
        %define datar ymm1

        vpxor ymm0, ymm0
        vpxor ymm1, ymm1
        vbroadcastf128 ymm15, [rsi] ; ymm15 = |salt|salt|

    .end:
        pop rbx
        pop r12
        pop rbp
        ret

; uint8_t* bcrypt_encrypt(uint8_t* plaintext,
;                           uint32_t plaintext_length,
;                           uint8_t* key,
;                           uint32_t key_length)

; bcrypt_encrypt:
;     ; rdi: pointer to plaintext string
;     ; rsi: string length
;     ; rdx: pointer to key
;     ; rcx: key length (in bits)
;     .build_frame:
;         push rbp
;         mov  rbp, rsp
;         push rbx
;         push r12
;         push r13
;         push r14

;     .allocate_for_subkeys:
;         ; keep values in untouchable registers!
;         mov rbx, rdi
;         mov r12, rsi
;         mov r13, rdx
;         mov r14, rcx
;         ; allocate space (address returned in rax)
;         mov rdi, P_ARRAY_LENGTH * P_VALUE_MEMORY_SIZE
;         call malloc
    
;     .initialise_for_key_schedule:
;         ; key pointer is already in r13
;         ; key length is already in r14
;         ; subkey pointer, i.e. target pointer, is already in rax
;         xor rdx, rdx ; clean for encryption
;         xor rdi, rdi ; clean for encryption
;         xor r8, r8 ; initialise P index
;         xor r15, r15 ; initialise key index
;         mov rsi, P_ARRAY
;         shr r14, 5 ; divide by 32 since we're counting 32-bit chunks
;         mov rcx, r14 ; initialise key counter
;         mov r9, P_ARRAY_LENGTH ; initialise P counter

;     .compute_subkeys:
;         ; at the end of this loop, rax will point to an array of encrypted P values
;         ; which should be used for the actual encryption loop
;         %define key edx
;         %define pvalue edi
;         %define pptr rsi
;         %define keyptr r13
;         %define targetptr rax
;         %define keycounter rcx
;         %define keyidx r15
;         %define pidx r8
;         %define pcounter r9
;         %define keylength r14
;         ; TODO: compare performance with reading two elements at a time (64 bit regs)
;         ; p displacement == target displacement
;         mov key, [keyptr + keyidx * P_VALUE_MEMORY_SIZE]
;         mov pvalue, [pptr + pidx * P_VALUE_MEMORY_SIZE]
;         xor pvalue, key ; encrypt
;         mov [targetptr + pidx], pvalue ; write subkey index
;         dec keycounter
;         jz  .reset_key_counter ; do modulus without really doing modulus
;         inc keyidx ; advance indices
        
;         .compute_subkeys_advance:
;         inc pidx
;         dec pcounter
;         jnz .compute_subkeys ; another loop iteration
;         jmp .initialise_for_encryption
        
;         .reset_key_counter:
;         mov keycounter, keylength
;         xor keyidx, keyidx
;         jmp .compute_subkeys_advance
    
;     .initialise_for_encryption:
;         ; NO LONGER NEEDED: key length, key pointer
;         ; NEEDED: target pointer (rax)

;     .encrypt:
    
;     .end:
;         pop r14
;         pop r13
;         pop r12
;         pop rbx
;         pop rbp
;         ret