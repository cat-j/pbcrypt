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

global variant


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

; unrolled loops, P-array in YMM registers, etc
variant: dw 2


section .text

%define salt    ymm0
%define p_0_7   ymm1
%define p_8_15  ymm2
%define p_16_17 xmm3

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;;;;;; MACROS ;;;;;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

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
; (or justify why you didn't)
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

; %1: key_data
; %2: key_data_low
; %3: key_data_ctr
; %4: key_ptr
; %5: key_len
; %6: loop_ctr
; %7: data
; %8: iteration number
%macro XOR_WITH_KEY 8
    .key_loop_%8:
        cmp %6, 8
        je  .end_key_loop_%8

        .extract_key_bytes_%8:
            cmp %3, %5
            jl  .continue_extract_%8
            xor %3, %3 ; reset counter

        .continue_extract_%8:
            mov %2, [%4 + %3] ; key_data_low, [key_ptr + key_data_ctr]
            shl %7, 8
            or  %7, %1

            inc %3
            inc %6
            jmp .key_loop_%8

    .end_key_loop_%8:
        rol %7, 32
        xor [rdi + BLF_CTX_P_OFFSET + %8*P_VALUE_MEMORY_SIZE], %7
        xor %6, %6
%endmacro

%macro READ_32_KEY_BYTES 8

    %define key_data     %1
    %define key_data_1   %2
    %define key_data_2   %3
    %define key_data_ctr %4
    %define key_ptr      %5
    %define key_len      %6
    %define loop_ctr     %7

    .lower_half_loop_%8:
        cmp     loop_ctr, 16
        je      .upper_half_loop_%8
        vpsrldq key_data, 1

        .extract_key_bytes_lower_%8:
            cmp     key_data_ctr, key_len
            jl      .continue_extract_lower_%8
            xor     key_data_ctr, key_data_ctr ; wrap around

        .continue_extract_lower_%8:
            vpinsrb key_data_1, [key_ptr + key_data_ctr], 15
            inc     loop_ctr
            inc     key_data_ctr
            jmp     .lower_half_loop_%8
    
    .upper_half_loop_%8:
        cmp     loop_ctr, 32
        je      .end_load_key_%8
        vpsrldq key_data_2, 1

        .extract_key_bytes_higher_%8:
            cmp key_data_ctr, key_len
            jl  .continue_extract_higher_%8
            xor key_data_ctr, key_data_ctr

        .continue_extract_higher_%8:
            vpinsrb key_data_2, [key_ptr + key_data_ctr], 15
            inc     loop_ctr
            inc     key_data_ctr
            jmp     .upper_half_loop_%8
        
    .end_load_key_%8:
        vinserti128 key_data, key_data_2, 1

%endmacro

; %1 -> ciphertext buffer
; %2: temporary register
; %3: temporary register
; %4: temporary register
; %5: lower 32 bits of %3
; %6 -> 24-byte ciphertext to be copied
%macro COPY_CTEXT 6
    %assign j 0
    %rep BCRYPT_WORDS / 2
        mov %2, [%6 + j*8]
        REVERSE_8_BYTES %2, %3, %4, %5
        rol %2, 32
        mov [%1 + j*8], %2
        %assign j j+1
    %endrep
%endmacro

; Keep salt and P-array cached
; %1 -> state
; %2 -> salt
%macro LOAD_SALT_AND_P 2
    vpxor    p_16_17, p_16_17
    vmovdqu  salt, [%2] ; TODO: align salt
    vmovdqa  p_0_7, [%1 + BLF_CTX_P_OFFSET]
    vmovdqa  p_8_15, [%1 + BLF_CTX_P_OFFSET + 8*P_VALUE_MEMORY_SIZE]
    vpinsrq  p_16_17, p_16_17, \
             [%1 + BLF_CTX_P_OFFSET + 16*P_VALUE_MEMORY_SIZE], 0
%endmacro


; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;; MACRO WRAPPERS ;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

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

; Intended exclusively for testing ciphertext copying macro
; void copy_ctext_asm(uint64_t *data, char *ctext)

copy_ctext_asm:
    ; rdi -> destination ciphertext
    ; rsi -> source ciphertext
    push rbp
    mov  rbp, rsp

    COPY_CTEXT rdi, rdx, rcx, r8, ecx, rsi

    pop rbp
    ret

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
    ; ymm0: salt
    ; ymm1, ymm2, ymm3: P-array
    
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        push r12
        push r13
        push r14
    
    ; LOAD_SALT_AND_P rdi, rsi

    .p_array_key:
        ; key_data: 32 bytes of key, wrapping
        ; key_data_ctr: byte index
        ; key_ptr: pointer to key
        ; key_len: key length in bytes
        ; data: all bytes read from the key, wrapping
        %define key_data     ymm4
        %define key_data_1   xmm4
        %define key_data_2   xmm5
        %define key_data_ctr r10
        %define key_ptr      rdx
        %define key_len      rcx
        %define loop_ctr     r12
        %define data         r13

        ; Initialise registers
        pxor key_data_1, key_data_1
        pxor key_data_2, key_data_2
        xor  key_data_ctr, key_data_ctr
        xor  loop_ctr, loop_ctr

        .p_0_7:
        READ_32_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 1
        vpxor key_data, p_0_7
        xor   loop_ctr, loop_ctr

        .p_8_15:
        READ_32_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 2
        vpxor key_data, p_8_15
        xor   loop_ctr, loop_ctr

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
        ; Encrypt 1024 P-elements, two per memory access -> 512 accesses
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

        LOAD_SALT_AND_P rdi, rbx

        call blowfish_expand_state_asm

        .expand_0_state:
            %define salt_ptr  rbx
            %define hash_ptr  r12
            %define key_ptr   r13
            %define key_len   r14
            %define rounds    r15
            %define round_ctr r8

            xor round_ctr, round_ctr
            
            .round_loop:
                cmp  round_ctr, rounds
                je   .encrypt

                mov  rsi, key_ptr
                mov  rdx, key_len
                call blowfish_expand_0_state_asm

                mov  rsi, salt_ptr
                call blowfish_expand_0_state_salt_asm

                inc  round_ctr
                jmp  .round_loop

    .encrypt:
        ; %1 -> ciphertext buffer
        ; %2: temporary register
        ; %3: temporary register
        ; %4: temporary register
        ; %5: lower 32 bits of %3
        ; %6 -> 24-byte ciphertext to be copied
        COPY_CTEXT hash_ptr, rdx, rcx, rax, ecx, initial_ctext

        %rep 64
            mov  rsi, hash_ptr
            call blowfish_encrypt_asm
        %endrep

        %assign i 0
        %rep 3
            xor rdx, rdx
            xor rcx, rcx
            mov rax, [hash_ptr + i*8]
            rol rax, 32
            REVERSE_8_BYTES rax, rdx, rcx, edx
            mov [hash_ptr + i*8], rax
            %assign i i+1
        %endrep
    
    .end:
        add rbp, 8
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret