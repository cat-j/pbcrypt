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

align 16
endianness_mask: db \
0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, \
0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c, \
0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14, \
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c

; unrolled loops, P-array in YMM registers, etc
variant: dw 2


section .text

%define salt                xmm0
%define p_0_7               ymm1
%define p_0_7x              xmm1
%define p_8_15              ymm2
%define p_8_15x             xmm2
%define p_16_17             xmm3
%define endianness_mask_ymm ymm15
%define endianness_mask_xmm xmm15

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;;;;;; MACROS ;;;;;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define ROTATE_128(Y) vpermq Y, Y, 0x4e

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
%endmacro

%macro F_BIG_ENDIAN 4
    %xdefine blf_state %1
    %xdefine x         %2
    %xdefine output    %3
    %xdefine tmp       %4
    
    ; output <- s[x & 0xff] + s[0x100 + (x>>8) & 0xff]
    mov tmp, x
    and tmp, 0xff
    mov output, [blf_state + tmp*S_ELEMENT_MEMORY_SIZE] ; s[x & 0xff]
    mov tmp, x
    shr tmp, 8
    and tmp, 0xff
    add output, [blf_state + S_BOX_MEMORY_SIZE + tmp*S_ELEMENT_MEMORY_SIZE]

    ; output <- output ^ s[0x200 + (x>>16) & 0xff]
    mov tmp, x
    shr tmp, 16
    and tmp, 0xff
    xor output, [blf_state + 2*S_BOX_MEMORY_SIZE + tmp*S_ELEMENT_MEMORY_SIZE]

    ; output <- output + s[0x300 + (x>>24) & 0xff]
    mov tmp, x
    shr tmp, 24
    and tmp, 0xff
    add output, [blf_state + 3*S_BOX_MEMORY_SIZE + tmp*S_ELEMENT_MEMORY_SIZE]
%endmacro

%macro BLOWFISH_ROUND_BIG_ENDIAN 7
    ; %xdefine blf_state %1
    ; %xdefine p_n       %2
    ; %xdefine i         %3
    ; %xdefine j         %4
    ; %xdefine f_output  %5
    ; %xdefine f_tmp     %6
    ; %xdefine r_tmp     %7

    F_BIG_ENDIAN %1, %4, %5, %6
    REVERSE_4_BYTES %5, %6, %7
    xor %5, %2
    xor %3, %5
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

; input:  | b3 | b2 | b1 | b0 |
; output: | b0 | b1 | b2 | b3 |
%macro REVERSE_4_BYTES 3
    ; %xdefine data %1
    ; %xdefine tmp1 %2
    ; %xdefine tmp2 %3

    mov %2, %1
    shr %2, 24
    and %2, 0xff     ; | 00 | 00 | 00 | b3 |

    mov %3, %1
    shr %3, 8        ; | 00 | b3 | b2 | b1 |
    and %3, 0xff00   ; | 00 | 00 | b2 | 00 |
    or  %2, %3       ; | 00 | 00 | b2 | b3 |

    mov %3, %1
    shl %3, 8        ; | b2 | b1 | b0 | 00 |
    and %3, 0xff0000 ; | 00 | b1 | 00 | 00 |
    or  %2, %3       ; | 00 | b1 | b2 | b3 |

    shl %1, 24       ; | b0 | 00 | 00 | 00 |
    or  %1, %2       ; | b0 | b1 | b2 | b3 |
%endmacro

; %1: input
; %2: temp
; %3: output
; %4: lower 32 bits of %2
%macro REVERSE_ENDIANNESS_2_DWORDS 4
    mov %2, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shr %2, 8          ; | 00 | b7 | b6 | b5 | b4 | b3 | b2 | b1 |
    and %4, 0xff000000 ; | 00 | 00 | 00 | 00 | b4 | 00 | 00 | 00 |

    mov %3, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shr %3, 24         ; | 00 | 00 | 00 | b7 | b6 | b5 | b4 | b3 |
    and %3, 0xff0000   ; | 00 | 00 | 00 | 00 | 00 | b5 | 00 | 00 |
    or  %2, %3         ; | 00 | 00 | 00 | 00 | b4 | b5 | 00 | 00 |

    mov %3, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shr %3, 40         ; | 00 | 00 | 00 | 00 | 00 | b7 | b6 | b5 |
    and %3, 0xff00     ; | 00 | 00 | 00 | 00 | 00 | 00 | b6 | 00 |
    or  %2, %3         ; | 00 | 00 | 00 | 00 | b4 | b5 | b6 | 00 |

    mov %3, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shr %3, 56         ; | 00 | 00 | 00 | 00 | 00 | 00 | 00 | b7 |
    or  %3, %2         ; | 00 | 00 | 00 | 00 | b4 | b5 | b6 | b7 |
    shl %3, 32         ; | b4 | b5 | b6 | b7 | 00 | 00 | 00 | 00 |

    mov %2, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shl %2, 24         ; | b4 | b3 | b2 | b1 | b0 | 00 | 00 | 00 |
    and %4, 0xff000000 ; | 00 | 00 | 00 | 00 | b0 | 00 | 00 | 00 |
    or  %3, %2         ; | b4 | b5 | b6 | b7 | b0 | 00 | 00 | 00 |

    mov %2, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shl %2, 8          ; | b6 | b5 | b4 | b3 | b2 | b1 | b0 | 00 |
    and %2, 0xff0000   ; | 00 | 00 | 00 | 00 | 00 | b1 | 00 | 00 |
    or  %3, %2         ; | b4 | b5 | b6 | b7 | b0 | b1 | 00 | 00 |

    mov %2, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shr %2, 8          ; | 00 | b7 | b6 | b5 | b4 | b3 | b2 | b1 |
    and %2, 0xff00     ; | 00 | 00 | 00 | 00 | 00 | 00 | b2 | 00 |
    or  %3, %2         ; | b4 | b5 | b6 | b7 | b0 | b1 | b2 | 00 |

    mov %2, %1         ; | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |
    shr %2, 24         ; | 00 | 00 | 00 | b7 | b6 | b5 | b4 | b3 |
    and %2, 0xff       ; | 00 | 00 | 00 | 00 | 00 | 00 | 00 | b3 |
    or  %3, %2         ; | b4 | b5 | b6 | b7 | b0 | b1 | b2 | b3 |
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

; %8: iteration number
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
            cmp     key_data_ctr, key_len
            jl      .continue_extract_higher_%8
            xor     key_data_ctr, key_data_ctr

        .continue_extract_higher_%8:
            vpinsrb key_data_2, [key_ptr + key_data_ctr], 15
            inc     loop_ctr
            inc     key_data_ctr
            jmp     .upper_half_loop_%8
        
    .end_load_key_%8:
        vinserti128 key_data, key_data_2, 1

%endmacro

%macro READ_8_KEY_BYTES 8
    .key_loop_%8:
        cmp     loop_ctr, 8
        je      .end_key_loop_%8
        vpsrldq key_data_1, 1
    
    .extract_key_bytes_%8:
        cmp     key_data_ctr, key_len
        jl      .continue_extract_%8
        xor     key_data_ctr, key_data_ctr

    .continue_extract_%8:
        vpinsrb key_data_1, [key_ptr + key_data_ctr], 7
        inc     loop_ctr
        inc     key_data_ctr
        jmp     .key_loop_%8
    
    .end_key_loop_%8:
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
    ; r13:   | Xr | Xl |, each reversed
    .build_frame:
        push rbp
        mov  rbp, rsp
        push r8
        sub  rbp, 8

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
        vpextrd p_value, p_0_7x, 0
        xor     x_l, p_value

        ; Blowfish rounds with P[1], ..., P[3]
        vpextrd p_value, p_0_7x, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_0_7x, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_0_7x, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ; Move P[4], ..., P[7] to lower part of the YMM register
        ROTATE_128(p_0_7)

        ; Blowfish rounds with P[4], ..., P[7]
        vpextrd p_value, p_0_7x, 0
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_0_7x, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_0_7x, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_0_7x, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ROTATE_128(p_0_7)

        ; Blowfish rounds with P[8], ..., P[11]
        vpextrd p_value, p_8_15x, 0
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_15x, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_15x, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_15x, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ; Move P[12], ..., P[15] to lower part of the YMM register
        ROTATE_128(p_8_15)

        ; Blowfish rounds with P[12], ..., P[15]
        vpextrd p_value, p_8_15x, 0
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_15x, 1
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        vpextrd p_value, p_8_15x, 2
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_l_64, x_r_64, tmp1, tmp2, tmp3
            
        .fucked_up:
        vpextrd p_value, p_8_15x, 3
        BLOWFISH_ROUND_BIG_ENDIAN blf_state, p_value_64, \
            x_r_64, x_l_64, tmp1, tmp2, tmp3

        ; Rotate 128 bits back
        ROTATE_128(p_8_15)

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
    
    .p_array_key:
        ; key_data: 32 bytes of key, wrapping
        ; key_data_1: lower 16 bytes of key_data
        ; key_data_2: helper for loading into key_data
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
        vpxor p_0_7, key_data
        xor   loop_ctr, loop_ctr

        .p_8_15:
        READ_32_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 2
        vpxor p_8_15, key_data
        xor   loop_ctr, loop_ctr

        .p_16_17:
        pxor key_data_1, key_data_1
        READ_8_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 3
        pxor  p_16_17, key_data_1
        xor   loop_ctr, loop_ctr

    .p_array_salt:
        %define data   r13
        %define salt_l r10
        %define salt_r r14
        %define tmp1   rbx
        %define tmp2   r15
        %define tmp1l  ebx

        xor    data, data      ; | 0000 0000 | 0000 0000 |
        pextrq salt_l, salt, 0 ; leftmost 64 bits of salt =  Xl | Xr
        pextrq salt_r, salt, 1 ; rightmost 64 bits of salt = Xl | Xr 

        ; Write to P[0], ... , P[3]
        xor    data, salt_l
        call   blowfish_encipher_register
        pinsrq p_0_7x, data, 0 ; 0 and 1

        xor    data, salt_r
        call   blowfish_encipher_register
        pinsrq p_0_7x, data, 1 ; 2 and 3

        ; Write to P[4], ... , P[7]
        xor    data, salt_l
        call   blowfish_encipher_register
        ROTATE_128(p_0_7)
        pinsrq p_0_7x, data, 0 ; 4 and 5
        ROTATE_128(p_0_7)

        xor    data, salt_r
        call   blowfish_encipher_register
        ROTATE_128(p_0_7)
        pinsrq p_0_7x, data, 1 ; 6 and 7
        ROTATE_128(p_0_7)

        ; Write to P[8], ... , P[11]
        xor    data, salt_l
        call   blowfish_encipher_register
        pinsrq p_8_15x, data, 0 ; 8 and 9

        xor    data, salt_r
        call   blowfish_encipher_register
        pinsrq p_8_15x, data, 1 ; 10 and 11

        ; Write to P[12], ... , P[15]
        xor    data, salt_l
        call   blowfish_encipher_register
        ROTATE_128(p_8_15)
        pinsrq p_8_15x, data, 0 ; 12 and 13
        ROTATE_128(p_8_15)

        xor    data, salt_r
        call   blowfish_encipher_register
        ROTATE_128(p_8_15)
        pinsrq p_8_15x, data, 1 ; 14 and 15
        ROTATE_128(p_8_15)

        ; Write to P[16] and P[17]
        xor    data, salt_l
        call   blowfish_encipher_register
        pinsrq p_16_17, data, 0

    .s_boxes_salt:
        %assign i 0
        %rep 256
            xor  data, salt_r
            call blowfish_encipher_register
            REVERSE_ENDIANNESS_2_DWORDS data, tmp1, tmp2, tmp1l
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], tmp2
            %assign i i+2

            xor  data, salt_l
            call blowfish_encipher_register
            REVERSE_ENDIANNESS_2_DWORDS data, tmp1, tmp2, tmp1l
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], tmp2
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
        ; key_data: 32 bytes of key, wrapping
        ; key_data_1: lower 16 bytes of key_data
        ; key_data_2: helper for loading into key_data
        ; key_data_ctr: byte index
        ; key_ptr: pointer to key
        ; key_len: key length in bytes
        ; data: all bytes read from the key, wrapping
        %define key_data     ymm4
        %define key_data_1   xmm4
        %define key_data_2   xmm5
        %define key_data_ctr r10
        %define key_ptr      rsi
        %define key_len      rdx
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
        vpxor p_0_7, key_data
        xor   loop_ctr, loop_ctr

        .p_8_15:
        READ_32_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 2
        vpxor p_8_15, key_data
        xor   loop_ctr, loop_ctr

        .p_16_17:
        pxor key_data_1, key_data_1
        READ_8_KEY_BYTES key_data, key_data_1, key_data_2, \
            key_data_ctr, key_ptr, key_len, loop_ctr, 3
        pxor  p_16_17, key_data_1
        xor   loop_ctr, loop_ctr
    
    .p_array_data:
        %define data   r13

        xor data, data ; 0

        ; Write to P[0], ... , P[3]
        call   blowfish_encipher_register
        pinsrq p_0_7x, data, 0 ; 0 and 1

        call   blowfish_encipher_register
        pinsrq p_0_7x, data, 1 ; 2 and 3

        ; Write to P[4], ... , P[7]
        call   blowfish_encipher_register
        ROTATE_128(p_0_7)
        pinsrq p_0_7x, data, 0 ; 4 and 5
        ROTATE_128(p_0_7)

        call   blowfish_encipher_register
        ROTATE_128(p_0_7)
        pinsrq p_0_7x, data, 1 ; 6 and 7
        ROTATE_128(p_0_7)

        ; Write to P[8], ... , P[11]
        call   blowfish_encipher_register
        pinsrq p_8_15x, data, 0 ; 8 and 9

        call   blowfish_encipher_register
        pinsrq p_8_15x, data, 1 ; 10 and 11

        ; Write to P[12], ... , P[15]
        call   blowfish_encipher_register
        ROTATE_128(p_8_15)
        pinsrq p_8_15x, data, 0 ; 12 and 13
        ROTATE_128(p_8_15)

        call   blowfish_encipher_register
        ROTATE_128(p_8_15)
        pinsrq p_8_15x, data, 1 ; 14 and 15
        ROTATE_128(p_8_15)

        ; Write to P[16] and P[17]
        call   blowfish_encipher_register
        pinsrq p_16_17, data, 0
    
    .s_boxes_data:
        ; Encrypt 1024 P-elements, two per memory access -> 512 accesses
        %assign i 0
        %rep 512
            call blowfish_encipher_register
            REVERSE_ENDIANNESS_2_DWORDS data, tmp1, tmp2, tmp1l
            mov  [rdi + i*S_ELEMENT_MEMORY_SIZE], tmp2
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