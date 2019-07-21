; C functions
extern malloc
extern free

; variables
extern initstate_asm

; exported functions
global blowfish_init_state_asm
global blowfish_expand_state_asm
global blowfish_encipher_asm

global f_asm
global blowfish_round_asm
global reverse_bytes
; global bcrypt_encrypt

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

section .text

; TODO: see if this can be optimised by indexing
; with an 8-bit register instead of using & 0xff

; Function for Feistel network
; %1 -> array of S-boxes
; %2: data
; %3: temporary register for shifting data (modified)
; %4: output (modified)
%macro F 4
    ; %4 <- S[0][x >> 24] + S[1][x >> 16 & 0xff]
    mov %3, %2
    shr %3, 24 ; highest 8 bits
    and %3, 0xff
    mov %4, [%1 + %3*S_ELEMENT_MEMORY_SIZE]
    mov %3, %2
    shr %3, 16
    and %3, 0xff ; second-highest 8 bits
    add %1, S_BOX_MEMORY_SIZE ; move to next S-box
    add %4, [%1 + %3*S_ELEMENT_MEMORY_SIZE]

    ; %4 <- %4 ^ S[2][x >> 8 & 0xff]
    mov %3, %2
    shr %3, 8
    and %3, 0xff ; second-lowest 8 bits
    add %1, S_BOX_MEMORY_SIZE ; move to next S-box
    xor %4, [%1 + %3*S_ELEMENT_MEMORY_SIZE]

    ; %4 <- %4 + S[3][x & 0xff]
    mov %3, %2
    and %3, 0xff ; lowest 8 bits
    add %1, S_BOX_MEMORY_SIZE ; move to next S-box
    add %4, [%1 + %3*S_ELEMENT_MEMORY_SIZE]
%endmacro

; %1 -> array of S-boxes
; %2: temporary register for F (modified)
; %3: data half
; %4: other data half
; %5: value read from P-array, p[n]
; %6: temporary register for F output (modified)
; BLOWFISH_ROUND s, t1, i, j, p[n], t2
%macro BLOWFISH_ROUND 6
    F %1, %4, %2, %6 ; %6 <- F(%1, %4) = F(s, j)
    xor %6, %5       ; %6 <- F(s, j) ^ p[n]
    xor %3, %6       ;  i <- i ^ F(s, j) ^ p[n]
    ; mov %3, %6 ; i <- i ^ p[n]
%endmacro

; %1: | l | r |, then | 0 | r |
; %2: |garbage|, then | 0 | l |
%macro SPLIT_L_R 2
    mov %2, %1
    shl %1, 32
    shr %1, 32
    shr %2, 32
%endmacro

; TODO: see if this is faster with shifts
; input:  | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
; output: | b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7 |
; %1: input, then output
; %2: temp
; %3: temp
; %4: lower 32 bits of %2
%macro REVERSE_8_BYTES 4
    mov %3, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shl %3, 56         ; | b0 | 00 | 00 | 00 | 00 | 00 | 00 | 00 |
    
    mov %2, %1
    and %2, 0xff00     ; | 00 | 00 | 00 | 00 | 00 | 00 | b1 | 00 |
    shl %2, 40         ; | 00 | b1 | 00 | 00 | 00 | 00 | 00 | 00 |
    or  %3, %2         ; | b0 | b1 | 00 | 00 | 00 | 00 | 00 | 00 |

    mov %2, %1
    and %2, 0xff0000   ; | 00 | 00 | 00 | 00 | 00 | b2 | 00 | 00 |
    shl %2, 24         ; | 00 | 00 | b2 | 00 | 00 | 00 | 00 | 00 |
    or  %3, %2         ; | b0 | b1 | b2 | 00 | 00 | 00 | 00 | 00 |
    
    mov %2, %1
    and %4, 0xff000000 ; | 00 | 00 | 00 | 00 | b3 | 00 | 00 | 00 |
    shl %2, 8          ; | 00 | 00 | 00 | b3 | 00 | 00 | 00 | 00 |
    or  %3, %2         ; | b0 | b1 | b2 | b3 | 00 | 00 | 00 | 00 |

    mov %2, %1
    shr %2, 8          ; | 00 | b7 | b6 | b5 | b4 | b3 | b2 | b1 |
    and %4, 0xff000000 ; | 00 | 00 | 00 | 00 | b4 | 00 | 00 | 00 |
    or  %3, %2         ; | b0 | b1 | b2 | b3 | b4 | 00 | 00 | 00 |
    
    mov %2, %1
    shr %2, 24         ; | 00 | 00 | 00 | b7 | b6 | b5 | b4 | b3 |
    and %2, 0xff0000   ; | 00 | 00 | 00 | 00 | 00 | b5 | 00 | 00 |
    or  %3, %2         ; | b0 | b1 | b2 | b3 | b4 | b5 | 00 | 00 |

    mov %2, %1
    shr %2, 40         ; | 00 | 00 | 00 | 00 | 00 | b7 | b6 | b5 |
    and %2, 0xff00     ; | 00 | 00 | 00 | 00 | 00 | 00 | b6 | 00 |
    or  %3, %2         ; | b0 | b1 | b2 | b3 | b4 | b5 | b6 | 00 |

    shr %1, 56         ; | 00 | 00 | 00 | 00 | 00 | 00 | 00 | b7 |
    or  %1, %3         ; | b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7 |
%endmacro

; Intended exclusively for testing Feistel function
; uint32_t f_asm(uint32_t x, blf_ctx *state)

f_asm:
    ; rdi: data
    ; rsi -> blowfish state
    ; address MUST be 32-bit aligned
    push rbp
    mov  rbp, rsp

    F rsi, rdi, rdx, rax

    pop rbp
    ret

; Intended exclusively for testing Blowfish round
; uint32_t blowfish_round_asm(uint32_t xl, uint32_t xr, blf_ctx *state,
;                             uint32_t n)

blowfish_round_asm:
    ; rdi: left half of data block, Xl
    ; rsi: right half of data block, Xr
    ; rdx -> Blowfish state (array of S-boxes and P-array)
    ; rcx: P-array index
    push rbp
    mov  rbp, rsp

    mov  r8, [rdx + BLF_CTX_P_OFFSET + rcx*P_VALUE_MEMORY_SIZE] ; r8: P-value
    BLOWFISH_ROUND rdx, r9, rsi, rdi, r8, r10
    mov  rax, rsi

    pop rbp
    ret

; Intended exclusively for testing byte reversal macro
; uint64_t reverse_bytes(uint64_t data)

reverse_bytes:
    ; rdi: data
    push rbp
    mov  rbp, rsp

    REVERSE_8_BYTES rdi, rsi, rdx, esi
    mov rax, rdi

    pop rbp
    ret

; void blowfish_encipher_asm(blf_ctx *state, uint64_t *data)

blowfish_encipher_asm:
    ; rdi -> blowfish state
    ; rsi -> | Xl | Xr |
    .build_frame:
        push rbp
        mov  rbp, rsp

    .separate_Xl_Xr:
        mov rdx, [rsi]      ; rdx: | Xl | Xr |
        mov ecx, edx        ; rcx: | 00 | Xr |
        shr rdx, 32         ; rdx: | 00 | Xl |

        %define x_l       rdx
        %define x_r       rcx
        %define blf_state rdi
        %define p_array   r8
        %define tmp1      r9
        %define tmp2      r10
    
    .do_encipher:
        ; Read first two P elements
        lea p_array, [blf_state + BLF_CTX_P_OFFSET]
        mov tmp1, [p_array] ; tmp1: | P1 | P0 |
        SPLIT_L_R tmp1, tmp2

        ; Start enciphering
        ; macro parameters:
        ; BLOWFISH_ROUND s, t1, i, j, p[n], t2
        xor x_l, tmp1 ; Xl <- Xl ^ P[0]
        BLOWFISH_ROUND blf_state, r11, x_r, x_l, tmp2, rax
        sub blf_state, S_BOX_MEMORY_SIZE*3 ; it was modified for calculating F

        ; n is even and ranges 2 to 14
        ; n+1 is odd and ranges 3 to 15
        %rep 7
            lea p_array, [p_array + P_VALUE_MEMORY_SIZE*2]
            mov tmp1, [p_array] ; tmp1: | Pn+1 |  Pn  |
            SPLIT_L_R tmp1, tmp2
            BLOWFISH_ROUND blf_state, r11, x_l, x_r, tmp1, rax
            sub blf_state, S_BOX_MEMORY_SIZE*3
            BLOWFISH_ROUND blf_state, r11, x_r, x_l, tmp2, rax
            sub blf_state, S_BOX_MEMORY_SIZE*3
        %endrep

        ; Load P16 and P17 and perform remaining operations
        lea p_array, [p_array + P_VALUE_MEMORY_SIZE*2]
        mov tmp1, [p_array]
        SPLIT_L_R tmp1, tmp2
        BLOWFISH_ROUND blf_state, r11, x_l, x_r, tmp1, rax
        
        xor x_r, tmp2
    
    ; Flipped because of endianness
    .build_output:
        shl x_r, 32  ; | Xr | 00 |
        shl x_l, 32
        shr x_l, 32  ; | 00 | Xl |
        or  x_r, x_l ; | Xr | Xl |
        mov [rsi], x_r

    .end:
        pop rbp
        ret

; TODO: rename this
; WARNING: THIS DOES NOT FOLLOW CDECL
; MUST NOT TOUCH R10
blowfish_encipher:
    ; rdi -> blowfish state
    ; r13:   | Xl | Xr |
    .build_frame:
        push rbp
        mov  rbp, rsp

    .separate_Xl_Xr:
        mov rdx, r13 ; rdx: | Xl | Xr |
        mov ecx, edx ; rcx: | 00 | Xr |
        shr rdx, 32  ; rdx: | 00 | Xl |

        %define x_l       rdx
        %define x_r       rcx
        %define blf_state rdi
        %define p_array   r8
        %define tmp1      r9
        %define tmp2      r11
    
    .do_encipher:
        ; Read first two P elements
        lea p_array, [blf_state + BLF_CTX_P_OFFSET]
        mov tmp1, [p_array]  ; tmp1: | P1 | P0 |
        SPLIT_L_R tmp1, tmp2 ; tmp1: | 00 | P0 |  tmp2: | 00 | P1 |

        ; Start enciphering
        ; macro parameters:
        ; BLOWFISH_ROUND s, t1, i, j, p[n], t2
        xor x_l, tmp1 ; Xl <- Xl ^ P[0]
        BLOWFISH_ROUND blf_state, rsi, x_r, x_l, tmp2, rax ; BLFRND(s,p,xr,xl,1)
        sub blf_state, S_BOX_MEMORY_SIZE*3 ; it was modified for calculating F

        ; n is even and ranges 2 to 14
        ; n+1 is odd and ranges 3 to 15
        %rep 7
            lea p_array, [p_array + P_VALUE_MEMORY_SIZE*2]
            mov tmp1, [p_array] ; tmp1: | Pn+1 |  Pn  |
            SPLIT_L_R tmp1, tmp2
            BLOWFISH_ROUND blf_state, rsi, x_l, x_r, tmp1, rax
            sub blf_state, S_BOX_MEMORY_SIZE*3
            BLOWFISH_ROUND blf_state, rsi, x_r, x_l, tmp2, rax
            sub blf_state, S_BOX_MEMORY_SIZE*3
        %endrep

        ; Load P16 and P17 and perform remaining operations
        lea p_array, [p_array + P_VALUE_MEMORY_SIZE*2]
        mov tmp1, [p_array] ; tmp1: | P17 | P16 |
        SPLIT_L_R tmp1, tmp2
        BLOWFISH_ROUND blf_state, rsi, x_l, x_r, tmp1 , rax
        sub blf_state, S_BOX_MEMORY_SIZE*3
        
        xor x_r, tmp2

    .build_output:
        shl x_l, 32  ; | Xl | 00 |
        shl x_r, 32
        shr x_r, 32  ; | 00 | Xr |
        or  x_r, x_l ; | Xl | Xr |
        mov r13, x_r

    .end:
        pop rbp
        ret

; void blowfish_init_state_asm(blf_ctx *state)

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

; void blowfish_expand_state_asm(blf_ctx *state, const char *salt,
;                                uint16_t saltbytes,
;                                const char *key, uint16_t keybytes)

blowfish_expand_state_asm:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx:   salt length in bytes
    ; rcx -> 4 to 56 byte key
    ; r8:    key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r12
        push r13
        push r14
    
    .p_array_key:
        ; key_data: 8 bytes from key
        ; key_data_ctr: byte index
        %define key_data r9
        %define key_data_ctr r10

    .p_array_salt:
        %define data   r13
        %define salt_l r10
        %define salt_r r14
        %define tmp1   rbx
        %define tmp2   r9
        %define tmp1l  ebx

        xor data, data        ; 0
        mov salt_l, [rsi]     ; leftmost 64 bits of salt =  Xl | Xr
        mov salt_r, [rsi + 8] ; rightmost 64 bits of salt = Xl | Xr

        REVERSE_8_BYTES salt_l, tmp1, tmp2, tmp1l
        REVERSE_8_BYTES salt_r, tmp1, tmp2, tmp1l

        ; Write to P[0], ... , P[15]
        %assign i 0
        %rep 4
            xor  data, salt_l
            call blowfish_encipher
            mov  [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2

            xor  data, salt_r
            call blowfish_encipher
            mov  [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2
        %endrep

        ; Write to P[16] and P[17]
        xor  data, salt_l
        call blowfish_encipher
        mov  [rdi + BLF_CTX_P_OFFSET + 16*P_VALUE_MEMORY_SIZE], data
        rol  data, 32

    .s_boxes_salt:
        ; Encrypt 1024 P-elements, two per memory access -> 512 accesses
        ; Two accesses per repetition -> 256 repetitions
        %assign i 0
        %rep 256
            xor  data, salt_r
            call blowfish_encipher
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2

            xor  data, salt_l
            call blowfish_encipher
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2
        %endrep
    
    .end:
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret

; blowfish_expand_state_asm:
;     ; rdi -> blowfish state (modified)
;     ; rsi -> 128-bit salt
;     ; rdx:   salt length in bytes
;     ; rcx -> 4 to 56 byte key
;     ; r8:    key length in bytes
;     .build_frame:
;         push rbp
;         mov  rbp, rsp
;         push r12
;         push rbx
    
;     %define key_data r9
;     %define key_data_lower r9b
;     %define ctx_data r10

;     %define key_idx rbx
;     %define p_idx r11

;     %define key_ptr rcx
;     %define ctx_ptr rdi
    
;     %define key_data_ctr r12
;     %define key_len rcx

;     ; initialise regs
;     ; rdi+4096 -> P-array
;     ; rcx      -> key
;     ; r8:  key index
;     ; r9:  8 key bytes
;     ; r10: 8 XOR'd P-array bytes
;     ; initialise indices and key data at 0
;     .start:
;         xor key_idx, key_idx
;         xor p_idx, p_idx
;         xor key_data, key_data ; because a^0 = a

;     .xor_p_array_loop:
;         ; Read two P-elements per iteration
;         ; MIND THE ENDIANNESS: this is | P2k+1 |  P2k  |
;         mov ctx_data, [ctx_ptr + BLF_CTX_P_OFFSET + p_idx*P_VALUE_MEMORY_SIZE]
;         xor key_data_ctr, key_data_ctr

;         ; Read 8 key bytes in order to XOR them with P elements
;         .read_key_data:
;             cmp key_idx, key_len
;             jl  .continue
;             xor key_idx, key_idx ; wrap around key w/o modulus
;             .continue:
;             shl key_data, 8 ; next byte goes in lowest 8
;             mov key_data_lower, [key_ptr + key_idx] ; THIS IS SEGFAULTING BECAUSE IT CAN'T ACCESS RDX
;             inc key_idx
;             inc key_data_ctr
;             cmp key_data_ctr, 8
;             jl  .read_key_data
        
;         xor ctx_data, key_data
;         mov [ctx_ptr + BLF_CTX_P_OFFSET + p_idx], ctx_data ; overwrite P elements
;         add p_idx, 2 ; p-array is dword-indexed
;         cmp p_idx, 18
;         jl  .xor_p_array_loop
    
;     ; .encrypt_p_array:
;     ;     %define datal ymm0
;     ;     %define datar ymm1

;     ;     vpxor ymm0, ymm0
;     ;     vpxor ymm1, ymm1
;     ;     vbroadcastf128 ymm15, [rsi] ; ymm15 = |salt|salt|

;     .end:
;         pop rbx
;         pop r12
;         pop rbp
;         ret

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