/*
 * pbcrypt: parallel bcrypt for password cracking
 * Copyright (C) 2019  Catalina Juarros (catalinajuarros@protonmail.com)
 *
 * This file is part of pbcrypt.
 * 
 * pbcrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * pbcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.
*/

%include "bcrypt-macros.mac"

; single-data
global f_asm
global blowfish_round_asm
global reverse_bytes
global copy_ctext_asm

; multi-data
global f_xmm
global blowfish_round_xmm
global copy_ctext_xmm
global f_ymm
global blowfish_round_ymm
global copy_ctext_ymm


section .data

align 32
endianness_mask: db \
0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, \
0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c, \
0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14, \
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c

element_offset: dd 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7
gather_mask: times 8 dd 0x80000000


section .text

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;; MACRO WRAPPERS ;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Intended exclusively for testing Feistel function
; uint32_t f_xmm(p_blf_ctx *state, uint32_t *bytes)

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
; uint32_t f_ymm(pd_blf_ctx *state, uint32_t *bytes)

f_ymm:
    ; rdi -> parallel blowfish state
    ; rsi -> eight 32-bit data blocks from different keys
    %define data   ymm4
    %define output ymm5
    %define tmp1   ymm6
    %define tmp2   ymm7
    %define mask   ymm8

    push rbp
    mov  rbp, rsp

    vmovdqa element_offset_ymm, [element_offset]
    vmovdqa gather_mask_ymm, [gather_mask]

    vmovdqu data, [rsi]
    F_YMM rdi, data, output, tmp1, tmp2, mask
    vmovdqu [rsi], output

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

; void blowfish_round_xmm(const p_blf_ctx *state, uint32_t *xl, uint32_t *xr,
;                         uint32_t n)

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
    movdqu [rdx], xr_xmm

    pop rbp
    ret

; void blowfish_round_ymm(const p_blf_ctx *state, uint32_t *xl, uint32_t *xr,
;                         uint32_t n)

blowfish_round_ymm:
    ; rdi -> parallel blowfish state
    ; rsi -> eight 32-bit left halves from different keys
    ; rdx -> eight 32-bit right halves from different keys
    ; rcx: P-array index
    push rbp
    mov  rbp, rsp

    %define xl_ymm ymm0
    %define xr_ymm ymm1
    %define p_ymm  ymm2
    %define output ymm3
    %define tmp1   ymm4
    %define tmp2   ymm5
    %define mask   ymm6

    vmovdqa element_offset_ymm, [element_offset]
    vmovdqa gather_mask_ymm, [gather_mask]

    shl     rcx, 3 ; multiply by 8 because there are 8 copies of each
    vmovdqu xl_ymm, [rsi]
    vmovdqu xr_ymm, [rdx]
    vmovdqu p_ymm, [rdi + PD_BLF_CTX_P_OFFSET + rcx*P_VALUE_MEMORY_SIZE]

    BLOWFISH_ROUND_YMM rdi, p_ymm, xr_ymm, xl_ymm, output, tmp1, tmp2, mask
    vmovdqu [rdx], xr_ymm

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
; void copy_ctext_asm(uint64_t *data, const char *ctext)

copy_ctext_asm:
    ; rdi -> destination ciphertext
    ; rsi -> source ciphertext
    push rbp
    mov  rbp, rsp

    COPY_CTEXT rdi, rdx, rcx, r8, ecx, rsi

    pop rbp
    ret

; Intended exclusively for testing ciphertext copying macro
; void copy_ctext_xmm(uint64_t *data, const char *ctext)

copy_ctext_xmm:
    ; rdi -> destination ciphertext
    ; rsi -> source ciphertext
    push rbp
    mov  rbp, rsp

    vmovdqa endianness_mask_ymm, [endianness_mask]
    COPY_CTEXT_XMM rdi, rsi, ymm0

    pop rbp
    ret

; Intended exclusively for testing ciphertext copying macro
; void copy_ctext_ymm(uint64_t *data, const char *ctext)

copy_ctext_ymm:
    ; rdi -> destination ciphertext
    ; rsi -> source ciphertext
    push rbp
    mov  rbp, rsp

    vmovdqa endianness_mask_ymm, [endianness_mask]
    COPY_CTEXT_YMM rdi, rsi, ymm0

    pop rbp
    ret