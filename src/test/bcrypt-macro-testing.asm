%include "bcrypt-macros.mac"

; single-data
global f_asm
global blowfish_round_asm
global reverse_bytes
global copy_ctext_asm

; multi-data
global f_xmm

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
    movdqu [rsi], xmm5

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
