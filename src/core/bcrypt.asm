%include "bcrypt-macros.mac"

; C functions
extern malloc
extern free

; variables
extern initstate_asm
extern initial_ctext

; exported functions for bcrypt implementation
global blowfish_init_state_asm
global blowfish_expand_state_asm
global blowfish_expand_0_state_asm
global blowfish_expand_0_state_salt_asm
global blowfish_encipher_asm
global blowfish_encrypt_asm
global bcrypt_hashpass_asm


section .data

%define BCRYPT_WORDS 6


section .text

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;;;;; FUNCTIONS ;;;;;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; void blowfish_encipher_asm(blf_ctx *state, uint64_t *data)

blowfish_encipher_asm:
    ; rdi -> blowfish state
    ; rsi -> | Xl | Xr |
    .build_frame:
        push rbp
        mov  rbp, rsp

    .separate_xl_xr:
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

; WARNING: THIS DOES NOT FOLLOW CDECL. For internal use only.
blowfish_encipher_register:
    ; rdi -> blowfish state
    ; r13:   | Xl | Xr |
    .build_frame:
        push rbp
        mov  rbp, rsp
        push r8
        sub  rbp, 8

    .separate_xl_xr:
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
        add rbp, 8
        pop r8
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
        mov     rax, [initstate_asm + BLF_CTX_P_OFFSET + 64] ; last bytes
        mov     [rdi + BLF_CTX_P_OFFSET + 64], rax

    .end:
        pop rbp
        ret

; void blowfish_expand_state_asm(blf_ctx *state, const char *salt,
;                                const char *key, uint16_t keybytes)

blowfish_expand_state_asm:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> 4 to 56 byte key
    ; rcx:    key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r12
        push r13
        push r14
    
    .p_array_key:
        ; key_data: a byte from the key
        ; key_data_low: lower 8 bits of key_data
        ; key_data_ctr: byte index
        ; key_ptr: pointer to key
        ; key_len: key length in bytes
        ; data: all bytes read from the key, wrapping
        %define key_data     r9
        %define key_data_low r9b
        %define key_data_ctr r10
        %define key_ptr      rdx
        %define key_len      rcx
        %define loop_ctr     r12
        %define data         r13

        ; Initialise registers
        xor key_data, key_data
        xor key_data_ctr, key_data_ctr
        xor data, data
        xor loop_ctr, loop_ctr

        %assign j 0
        %rep 9
            XOR_WITH_KEY key_data, key_data_low, key_data_ctr, \
                key_ptr, key_len, loop_ctr, data, j
            %assign j j+2
        %endrep

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
            call blowfish_encipher_register
            mov  [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2

            xor  data, salt_r
            call blowfish_encipher_register
            mov  [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2
        %endrep

        ; Write to P[16] and P[17]
        xor  data, salt_l
        call blowfish_encipher_register
        mov  [rdi + BLF_CTX_P_OFFSET + 16*P_VALUE_MEMORY_SIZE], data
        rol  data, 32

    .s_boxes_salt:
        ; Encrypt 1024 S-elements, two per memory access -> 512 accesses
        ; Two accesses per repetition -> 256 repetitions
        %assign i 0
        %rep 256
            xor  data, salt_r
            call blowfish_encipher_register
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2

            xor  data, salt_l
            call blowfish_encipher_register
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

; void blowfish_expand_0_state_asm(blf_ctx *state, const char *key,
;                                  uint16_t keybytes)

blowfish_expand_0_state_asm:
    ; rdi -> state
    ; rsi -> key
    ; rdx:   key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp
        push r12
        push r13
    
    .p_array_key:
        ; key_data: a byte from the key
        ; key_data_low: lower 8 bits of key_data
        ; key_data_ctr: byte index
        ; key_ptr: pointer to key
        ; key_len: key length in bytes
        ; data: all bytes read from the key, wrapping
        %define key_data     r9
        %define key_data_low r9b
        %define key_data_ctr r10
        %define key_ptr      rsi
        %define key_len      rdx
        %define loop_ctr     r12
        %define data         r13
    
        ; Initialise registers
        xor key_data, key_data
        xor key_data_ctr, key_data_ctr
        xor data, data
        xor loop_ctr, loop_ctr

        %assign j 0
        %rep 9
            XOR_WITH_KEY key_data, key_data_low, key_data_ctr, \
                key_ptr, key_len, loop_ctr, data, j
            %assign j j+2
        %endrep
    
    .p_array_data:
        %define data   r13
        %define tmp1   rcx
        %define tmp2   r9
        %define tmp1l  ecx

        xor data, data ; 0

        %assign i 0
        %rep 9
            call blowfish_encipher_register
            mov  [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2
        %endrep
    
    .s_boxes_data:
        ; Encrypt 1024 P-elements, two per memory access -> 512 accesses
        %assign i 0
        %rep 512
            call blowfish_encipher_register
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2
        %endrep

    .end:
        pop r13
        pop r12
        pop rbp
        ret

; void blowfish_expand_0_state_salt_asm(blf_ctx *state, const char *salt)

blowfish_expand_0_state_salt_asm:
    ; rdi -> state
    ; rsi -> salt
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r13
        push r14
        sub  rbp, 8

    ; Bespoke variant of blowfish_expand_0_state_asm for optimised
    ; encryption with salt. No expensive key reading needed, as salt
    ; is always 128 bytes and each half can be kept in one register.

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
        rol salt_l, 32
        rol salt_r, 32

        %assign i 0
        %rep 4
            xor [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], salt_l
            %assign i i+2

            xor [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], salt_r
            %assign i i+2
        %endrep

        xor [rdi + BLF_CTX_P_OFFSET + 16*P_VALUE_MEMORY_SIZE], salt_l
    
    .p_array_data:
        %define data   r13
        %define tmp1   rcx
        %define tmp2   r9
        %define tmp1l  ecx

        xor data, data ; 0

        %assign i 0
        %rep 9
            call blowfish_encipher_register
            mov  [rdi + BLF_CTX_P_OFFSET + i*P_VALUE_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2
        %endrep
    
    .s_boxes_data:
        ; Encrypt 1024 P-elements, two per memory access -> 512 accesses
        %assign i 0
        %rep 512
            call blowfish_encipher_register
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], data
            rol  data, 32
            %assign i i+2
        %endrep
    
    .end:
        add rbp, 8
        pop r14
        pop r13
        pop rbx
        pop rbp
        ret

; void blowfish_encrypt_asm(blf_ctx *state, uint64_t *data)

blowfish_encrypt_asm:
    ; rdi -> state
    ; rsi -> 24-byte ciphertext
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r13

    .do_encrypt:
        %define data     r13
        %define ctext    rbx
        %define tmp1     rdx
        %define tmp2     rcx
        %define tmp1_low edx

        mov ctext, rsi

        %assign i 0
        %rep BCRYPT_WORDS / 2
            mov  data, [ctext + i*8]
            rol  data, 32
            call blowfish_encipher_register
            mov  [ctext + i*8], data
            %assign i i+1
        %endrep

    .end:
        pop r13
        pop rbx
        pop rbp
        ret

; void bcrypt_hashpass_asm(blf_ctx *state, const char *salt,
;                          const char *key, uint16_t keybytes,
;                          uint8_t *hash, uint64_t rounds)

bcrypt_hashpass_asm:
    ; rdi -> state
    ; rsi -> 128-bit salt
    ; rdx -> key
    ; rcx:   key length in bytes
    ; r8 ->  hash (modified)
    ; r9:    rounds
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r12
        push r13
        push r14
        push r15
        sub  rbp, 8

    .key_setup:
        ; Save these values because blowfish_expand_state_asm would modify them
        ; rbx -> salt
        ; r12 -> hash
        ; r13 -> key
        ; r14:   key length in bytes
        ; r15:   rounds
        mov rbx, rsi
        mov r12, r8
        mov r13, rdx
        mov r14, rcx
        mov r15, r9

        call blowfish_init_state_asm

        call blowfish_expand_state_asm

    ;     .expand_0_state:
    ;         %define salt_ptr  rbx
    ;         %define hash_ptr  r12
    ;         %define key_ptr   r13
    ;         %define key_len   r14
    ;         %define rounds    r15
    ;         %define round_ctr r8

    ;         xor round_ctr, round_ctr
            
    ;         .round_loop:
    ;             cmp  round_ctr, rounds
    ;             je   .encrypt

    ;             mov  rsi, key_ptr
    ;             mov  rdx, key_len
    ;             call blowfish_expand_0_state_asm

    ;             mov  rsi, salt_ptr
    ;             call blowfish_expand_0_state_salt_asm

    ;             inc  round_ctr
    ;             jmp  .round_loop

    ; .encrypt:
    ;     ; %1 -> ciphertext buffer
    ;     ; %2: temporary register
    ;     ; %3: temporary register
    ;     ; %4: temporary register
    ;     ; %5: lower 32 bits of %3
    ;     ; %6 -> 24-byte ciphertext to be copied
    ;     COPY_CTEXT hash_ptr, rdx, rcx, rax, ecx, initial_ctext

    ;     %rep 64
    ;         mov  rsi, hash_ptr
    ;         call blowfish_encrypt_asm
    ;     %endrep

    ;     %assign i 0
    ;     %rep 3
    ;         xor rdx, rdx
    ;         xor rcx, rcx
    ;         mov rax, [hash_ptr + i*8]
    ;         rol rax, 32
    ;         REVERSE_8_BYTES rax, rdx, rcx, edx
    ;         mov [hash_ptr + i*8], rax
    ;         %assign i i+1
    ;     %endrep
    
    .end:
        add rbp, 8
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret