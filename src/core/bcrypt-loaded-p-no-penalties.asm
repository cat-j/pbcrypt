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

; exported functions for testing macros
global f_asm
global blowfish_round_asm
global reverse_bytes
global copy_ctext_asm
global load_salt_and_p


section .data

align 32
endianness_mask: db \
0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, \
0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c, \
0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14, \
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c


section .text

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;; MACRO WRAPPERS ;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Intended exclusively for initialising YMM registers
; before testing key expansion functions
; void load_salt_and_p(blf_ctx *state, uint8_t *salt)

load_salt_and_p:
    ; rdi -> state
    ; rsi -> salt
    push rbp
    mov  rbp, rsp

    LOAD_SALT_AND_P rdi, rsi

    pop rbp
    ret


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
    ; r13:   | Xr | Xl |, each reversed
    .build_frame:
        push rbp
        mov  rbp, rsp
        push r8
        sub  rsp, 8

    .separate_xl_xr:
        mov rdx, r13 ; rdx: | Xr | Xl |
        mov ecx, edx ; rcx: | 00 | Xl |
        shr rdx, 32  ; rdx: | 00 | Xr |

        %define x_l        ecx
        %define x_r        edx
        %define x_l_64     rcx
        %define x_r_64     rdx
        %define blf_state  rdi
        %define p_value    r9d
        %define p_value_64 r9
        %define tmp1       r8
        %define tmp2       r11
        %define tmp3       rax
    
    .do_encipher:
        ; Encrypt with P[0]
        vpextrd p_value, p_0_3, 0
        xor     x_l, p_value

        ; Blowfish rounds with P[1], ..., P[3]
        vpextrd p_value, p_0_3, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_0_3, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_0_3, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ; Blowfish rounds with P[4], ..., P[7]
        vpextrd p_value, p_4_7, 0
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_4_7, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_4_7, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_4_7, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ; Blowfish rounds with P[8], ..., P[11]
        vpextrd p_value, p_8_11, 0
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_11, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_11, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_11, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ; Blowfish rounds with P[12], ..., P[15]
        vpextrd p_value, p_12_15, 0
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_12_15, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_12_15, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3
            
        vpextrd p_value, p_12_15, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ; Blowfish round with P[16]
        vpextrd p_value, p_16_17, 0
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        ; Encrypt with P[17] and flip
        vpextrd p_value, p_16_17, 1
        xor     x_r, p_value
    
    .build_output:
        shl x_r_64, 32     ; | Xr | 00 |
        shr x_r_64, 32     ; | 00 | Xr |
        shl x_l_64, 32     ; | Xl | 00 |
        or  x_l_64, x_r_64 ; | Xl | Xr |
        mov r13, x_l_64

    .end:
        add rsp, 8
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
    ; rcx:   key length in bytes
    ; ymm0: salt
    ; ymm1, ymm2, ymm3: P-array
    
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r12
        push r13
        push r14
        push r15
        sub  rsp, 8
    
    .p_array_key:
        ; key_data: 16 bytes of key, wrapping
        ; key_data_ctr: byte index
        ; key_ptr: pointer to key
        ; key_len: key length in bytes
        ; data: all bytes read from the key, wrapping
        ; key_data_1 and key_data_2 are leftovers from old implementation
        %define key_data     xmm7
        %define key_data_1   xmm7
        %define key_data_2   xmm8
        %define key_data_ctr r10
        %define key_ptr      rdx
        %define key_len      rcx
        %define loop_ctr     r12
        %define data         r13

        ; Initialise registers
        vpxor key_data, key_data
        xor   key_data_ctr, key_data_ctr
        xor   loop_ctr, loop_ctr

        .p_0_3:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 1
        vpxor p_0_3, key_data
        xor   loop_ctr, loop_ctr

        .p_4_7:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 2
        vpxor p_4_7, key_data
        xor   loop_ctr, loop_ctr

        .p_8_11:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 3
        vpxor p_8_11, key_data
        xor   loop_ctr, loop_ctr

        .p_12_15:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 4
        vpxor p_12_15, key_data
        xor   loop_ctr, loop_ctr

        .p_16_17:
        vpxor key_data_1, key_data_1
        READ_8_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 5
        vpxor  p_16_17, key_data_1
        xor    loop_ctr, loop_ctr

    .p_array_salt:
        %define data   r13
        %define salt_l r10
        %define salt_r r14
        %define tmp1   rbx
        %define tmp2   r15
        %define tmp1l  ebx
        %define tmp2l  r15d

        xor     data, data      ; | 0000 0000 | 0000 0000 |
        vpextrq salt_l, salt, 0 ; leftmost 64 bits of salt =  Xl | Xr
        vpextrq salt_r, salt, 1 ; rightmost 64 bits of salt = Xl | Xr 

        ; Write to P[0], ... , P[3]
        xor     data, salt_l
        call    blowfish_encipher_register
        vpinsrq p_0_3, data, 0 ; 0 and 1

        xor     data, salt_r
        call    blowfish_encipher_register
        vpinsrq p_0_3, data, 1 ; 2 and 3

        ; Write to P[4], ... , P[7]
        xor     data, salt_l
        call    blowfish_encipher_register
        vpinsrq p_4_7, data, 0 ; 4 and 5

        xor     data, salt_r
        call    blowfish_encipher_register
        vpinsrq p_4_7, data, 1 ; 6 and 7

        ; Write to P[8], ... , P[11]
        xor     data, salt_l
        call    blowfish_encipher_register
        vpinsrq p_8_11, data, 0 ; 8 and 9

        xor     data, salt_r
        call    blowfish_encipher_register
        vpinsrq p_8_11, data, 1 ; 10 and 11

        ; Write to P[12], ... , P[15]
        xor     data, salt_l
        call    blowfish_encipher_register
        vpinsrq p_12_15, data, 0 ; 12 and 13

        xor     data, salt_r
        call    blowfish_encipher_register
        vpinsrq p_12_15, data, 1 ; 14 and 15

        ; Write to P[16] and P[17]
        xor     data, salt_l
        call    blowfish_encipher_register
        vpinsrq p_16_17, data, 0

    .s_boxes_salt:
        %assign i 0
        %rep 256
            xor  data, salt_r
            call blowfish_encipher_register
            mov  tmp2, data
            REVERSE_ENDIANNESS_2_DWORDS_BSWAP tmp2, tmp1, tmp2l, tmp1l
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], tmp2
            %assign i i+2

            xor  data, salt_l
            call blowfish_encipher_register
            mov  tmp2, data
            REVERSE_ENDIANNESS_2_DWORDS_BSWAP tmp2, tmp1, tmp2l, tmp1l
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], tmp2
            %assign i i+2
        %endrep
    
    .end:
        add rsp, 8
        pop r15
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
        push rbx
        push r12
        push r13
        push r15
    
    .p_array_key:
        ; key_data: 16 bytes of key, wrapping
        ; key_data_1: lower 16 bytes of key_data
        ; key_data_2: helper for loading into key_data
        ; key_data_ctr: byte index
        ; key_ptr: pointer to key
        ; key_len: key length in bytes
        ; data: all bytes read from the key, wrapping
        %define key_data     xmm7
        %define key_data_1   xmm7
        %define key_data_2   xmm8
        %define key_data_ctr r10
        %define key_ptr      rsi
        %define key_len      rdx
        %define loop_ctr     r12
        %define data         r13

        ; Initialise registers
        vpxor key_data, key_data
        xor   key_data_ctr, key_data_ctr
        xor   loop_ctr, loop_ctr

        .p_0_3:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 1
        vpxor p_0_3, key_data
        xor   loop_ctr, loop_ctr

        .p_4_7:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 2
        vpxor p_4_7, key_data
        xor   loop_ctr, loop_ctr

        .p_8_11:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 3
        vpxor p_8_11, key_data
        xor   loop_ctr, loop_ctr

        .p_12_15:
        READ_16_KEY_BYTES key_data, key_data_ctr, key_ptr, \
            key_len, loop_ctr, 4
        vpxor p_12_15, key_data
        xor   loop_ctr, loop_ctr

        .p_16_17:
        vpxor key_data_1, key_data_1
        READ_8_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 5
        vpxor  p_16_17, key_data_1
        xor    loop_ctr, loop_ctr
    
    .p_array_data:
        %define data   r13

        xor data, data ; 0

        ; Write to P[0], ... , P[3]
        call    blowfish_encipher_register
        vpinsrq p_0_3, data, 0 ; 0 and 1

        call    blowfish_encipher_register
        vpinsrq p_0_3, data, 1 ; 2 and 3

        ; Write to P[4], ... , P[7]
        call    blowfish_encipher_register
        vpinsrq p_4_7, data, 0 ; 4 and 5

        call    blowfish_encipher_register
        vpinsrq p_4_7, data, 1 ; 6 and 7

        ; Write to P[8], ... , P[11]
        call    blowfish_encipher_register
        vpinsrq p_8_11, data, 0 ; 8 and 9

        call    blowfish_encipher_register
        vpinsrq p_8_11, data, 1 ; 10 and 11

        ; Write to P[12], ... , P[15]
        call    blowfish_encipher_register
        vpinsrq p_12_15, data, 0 ; 12 and 13

        call    blowfish_encipher_register
        vpinsrq p_12_15, data, 1 ; 14 and 15

        ; Write to P[16] and P[17]
        call    blowfish_encipher_register
        vpinsrq p_16_17, data, 0
    
    .s_boxes_data:
        %define tmp1  rbx
        %define tmp2  ebx
        %define tmp2  r15
        %define tmp2l r15d

        ; Encrypt 1024 P-elements, two per memory access -> 512 accesses
        %assign i 0
        %rep 512
            call blowfish_encipher_register
            mov  tmp2, data
            REVERSE_ENDIANNESS_2_DWORDS_BSWAP tmp2, tmp1, tmp2l, tmp1l
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], tmp2
            %assign i i+2
        %endrep

    .end:
        pop r15
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret

; void blowfish_expand_0_state_salt_asm(blf_ctx *state, const char *salt)

blowfish_expand_0_state_salt_asm:
    ; rdi -> state
    ; rsi -> salt (unused)
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r13
        push r14
        push r15

    ; Bespoke variant of blowfish_expand_0_state_asm for optimised
    ; encryption with salt. No expensive key reading needed, as salt
    ; is always 128 bytes and each half can be kept in one register.

    .p_array_salt:
        vpxor p_0_3, salt
        vpxor p_4_7, salt
        vpxor p_8_11, salt
        vpxor p_12_15, salt
        pxor  p_16_17, salt
    
    .p_array_data:
        %define data   r13

        xor data, data ; 0

        ; Write to P[0], ... , P[3]
        call    blowfish_encipher_register
        vpinsrq p_0_3, data, 0 ; 0 and 1

        call    blowfish_encipher_register
        vpinsrq p_0_3, data, 1 ; 2 and 3

        ; Write to P[4], ... , P[7]
        call    blowfish_encipher_register
        vpinsrq p_4_7, data, 0 ; 4 and 5

        call    blowfish_encipher_register
        vpinsrq p_4_7, data, 1 ; 6 and 7

        ; Write to P[8], ... , P[11]
        call    blowfish_encipher_register
        vpinsrq p_8_11, data, 0 ; 8 and 9

        call    blowfish_encipher_register
        vpinsrq p_8_11, data, 1 ; 10 and 11

        ; Write to P[12], ... , P[15]
        call    blowfish_encipher_register
        vpinsrq p_12_15, data, 0 ; 12 and 13

        call    blowfish_encipher_register
        vpinsrq p_12_15, data, 1 ; 14 and 15

        ; Write to P[16] and P[17]
        call    blowfish_encipher_register
        vpinsrq p_16_17, data, 0
    
    .s_boxes_data:
        %define tmp1   rcx
        %define tmp2   r9
        %define tmp1l  ecx
        %define tmp2l  r9d

        ; Encrypt 1024 P-elements, two per memory access -> 512 accesses
        %assign i 0
        %rep 512
            call blowfish_encipher_register
            mov  tmp2, data
            REVERSE_ENDIANNESS_2_DWORDS_BSWAP tmp2, tmp1, tmp2l, tmp1l
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], tmp2
            %assign i i+2
        %endrep
    
    .end:
        pop r15
        pop r14
        pop r13
        pop rbx
        pop rbp
        ret

; void blowfish_encrypt_asm(blf_ctx *state, uint64_t *data)

blowfish_encrypt_asm:
    ; rdi -> state
    ; ymm4:  24-byte ciphertext
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r13

    .do_encrypt:
        %define data     r13
        %define tmp1     rdx
        %define tmp2     rcx
        %define tmp1_low edx

        pextrq data, ctext_x, 0 ; two data halves from ciphertext
        call   blowfish_encipher_register
        pinsrq ctext_x, data, 0

        pextrq data, ctext_x, 1
        call   blowfish_encipher_register
        pinsrq ctext_x, data, 1

        ROTATE_128(ctext_y)

        pextrq data, ctext_x, 0
        call   blowfish_encipher_register
        pinsrq ctext_x, data, 0

        ROTATE_128(ctext_y)

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
        sub  rsp, 8

    .key_setup:
        %define key_ptr   rbx
        %define key_len   r12
        %define rounds    r13
        %define round_ctr r14
        %define hash_ptr  r15

        ; Save these values because blowfish_expand_state_asm would modify them
        mov  rbx, rdx ; key pointer
        mov  r12, rcx ; key length
        mov  r13, r9  ; rounds
        mov  r15, r8  ; hash

        call blowfish_init_state_asm

        LOAD_SALT_AND_P_NO_PENALTIES rdi, rsi

        call blowfish_expand_state_asm

        .expand_0_state:
            xor round_ctr, round_ctr ; initialise at 0

            .round_loop:
                cmp round_ctr, rounds
                je  .encrypt

                mov  rsi, key_ptr
                mov  rdx, key_len
                call blowfish_expand_0_state_asm

                call blowfish_expand_0_state_salt_asm

                inc round_ctr
                jmp .round_loop

    .encrypt:
        ; %1 -> ciphertext buffer
        ; %2: temporary register
        ; %3: temporary register
        ; %4: temporary register
        ; %5: lower 32 bits of %3
        ; %6 -> 24-byte ciphertext to be copied
        LOAD_CTEXT initial_ctext

        %rep 64
            call blowfish_encrypt_asm
        %endrep

        STORE_P rdi, rax
        STORE_CTEXT hash_ptr, rax
    
    .end:
        add rsp, 8
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret