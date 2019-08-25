%include "bcrypt-macros.mac"

; variables
extern initstate_asm

; exported functions for testing macros
global f_xmm

global variant


section .data

; unrolled loops, P-array in YMM registers, etc
variant: dw 3


section .text

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;; MACRO WRAPPERS ;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Intended exclusively for testing Feistel function
; uint32_t f_asm(blf_ctx *state, uint32_t *bytes)

f_xmm:
    ; rdi -> blowfish state
    ; rsi -> four 32-bit data blocks from different keys
    push rbp
    mov  rbp, rsp

    movdqu xmm4, [rsi]
    F_XMM rdi, xmm4, xmm5, xmm6, xmm7, xmm8

    pop rbp
    ret


; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;;;;; FUNCTIONS ;;;;;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

blowfish_parallelise_state:
    ; rdi -> parallel blowfish state (4 keys)
    ; rsi -> single-key blowfish state
    ; address MUST be 32-bit aligned
    .build_frame:
        push rbp
        mov  rbp, rsp
    
    .copy_S_boxes:
        %define two_elements        rdx
        %define one_element         edx
        %define parallel_elements_y ymm1
        %define parallel_elements_x xmm1
        %define writemask           ymm2

        %assign i 0
        ; 4 256-element boxes => 1024 elements
        ; 4 bytes per element => 4096 bytes total
        ; 2 elements per extended register => 4096/2 = 2048 accesses to copy all the boxes
        %rep    2048
            mov          two_elements, [rsi + i*S_ELEMENT_MEMORY_SIZE*2]
            rol          two_elements, 32
            vpbroadcastd parallel_elements_x, one_element
            rol          two_elements, 32
            ROTATE_128(parallel_elements_y)
            vpbroadcastd parallel_elements_x, one_element
            vmovdqa      [rdi + i*YMM_SIZE], parallel_elements_y
            %assign i i+1
        %endrep

    .copy_P_array:
        %rep 9
            ; P elements are the same size as S elements
            mov          two_elements, [rsi + i*S_ELEMENT_MEMORY_SIZE*2]
            rol          two_elements, 32
            vpbroadcastd parallel_elements_x, one_element
            rol          two_elements, 32
            ROTATE_128(parallel_elements_y)
            vpbroadcastd parallel_elements_x, one_element
            vmovdqa      [rdi + i*YMM_SIZE], parallel_elements_y
        %endrep
    
    .end:
        pop rbp
        ret

blowfish_init_state_parallel:
    ; rdi -> parallel blowfish state (modified)
    ; rsi -> parallel blowfish state to be copied
    ; both addresses MUST be 32-bit aligned
    .build_frame:
        push rbp
        mov  rbp, rsp
    
    .copy_all:
        %define eight_elements ymm1
        ; 4096 S elements + 18 P elements = 4114 elements
        ; 4 copies per element => 16456 elements
        ; 8 elements per YMM => 16456/8 = 2057 accesses
        %assign i 0
        %rep    2057
            vmovdqa eight_elements, [rsi + i*YMM_SIZE]
            vmovdqa [rdi + i*YMM_SIZE], eight_elements
            %assign i i+1
        %endrep

    .end:
        pop rbp
        ret