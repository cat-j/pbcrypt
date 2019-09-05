%include "bcrypt-macros.mac"

; single-data
global f_asm
global blowfish_round_asm
global reverse_bytes
global copy_ctext_asm

; multi-data
global f_xmm


section .data

align 32
element_offset: dd 0x0, 0x1, 0x2, 0x3
gather_mask: times 4 dd 0x80000000


section .text

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;; MACRO WRAPPERS ;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Intended exclusively for testing Feistel function
; uint32_t f_asm(blf_ctx *state, uint32_t *bytes)

f_xmm:
    ; rdi -> parallel blowfish state
    ; rsi -> four 32-bit data blocks from different keys
    %define data   xmm4
    %define output xmm5
    %define tmp1   xmm6
    %define tmp2   xmm7
    %define mask   xmm8

    push rbp
    mov  rbp, rsp

    movdqa element_offset_xmm, [element_offset]
    movdqa gather_mask_xmm, [gather_mask]

    movdqu data, [rsi]
    F_XMM rdi, data, output, tmp1, tmp2, mask
    movdqu [rsi], output

    pop rbp
    ret

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

blowfish_round_xmm:
    ; rdi -> parallel blowfish state
    ; rsi -> four 32-bit left halves from different keys
    ; rdx -> four 32-bit right halves from different keys
    ; rcx: P-array index
    push rbp
    mov  rbp, rsp

    %define xl_xmm xmm0
    %define xr_xmm xmm1
    %define p_xmm  xmm2
    %define output xmm3
    %define tmp1   xmm4
    %define tmp2   xmm5
    %define mask   xmm6

    shl    rcx, 2 ; multiply by 4 because there are 4 copies of each
    movdqu xl_xmm, [rsi]
    movdqu xr_xmm, [rdx]
    movdqu p_xmm, [rdi + P_BLF_CTX_P_OFFSET + rcx*P_VALUE_MEMORY_SIZE]

    BLOWFISH_ROUND_XMM rdi, p_xmm, xr_xmm, xl_xmm, output, tmp1, tmp2, mask
    movdqu [rdx], output

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
