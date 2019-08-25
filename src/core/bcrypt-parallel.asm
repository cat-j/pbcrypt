%include "bcrypt-macros.mac"

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