;
; pbcrypt: parallel bcrypt for password cracking
; Copyright (C) 2019  Catalina Juarros <https://github.com/cat-j>
;
; This file is part of pbcrypt.
; 
; pbcrypt is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 2 of the License, or
; (at your option) any later version.
; 
; pbcrypt is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License
; along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.
;

; Many functions from the parallel implementation of bcrypt
; require some YMM registers be pre-loaded, and calling them
; from C cannot guarantee this.
; These wrappers are intended for testing the parallel functions
; without using inline ASM.

%include "bcrypt-macros.mac"

; Functions to be wrapped
extern blowfish_expand_state_parallel_double
extern blowfish_expand_0_state_parallel_double
extern blowfish_expand_0_state_salt_parallel_double

; Exported functions
global blowfish_expand_state_parallel_double_wrapper
global blowfish_expand_0_state_parallel_double_wrapper
global blowfish_expand_0_state_salt_parallel_double_wrapper


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

blowfish_expand_state_parallel_double_wrapper:
    ; rdi -> parallel blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> array of four 4 to 56 byte keys
    ; rcx:   key length
    push rbp
    mov  rbp, rsp

    vmovdqa endianness_mask_ymm, [endianness_mask]
    vmovdqa gather_mask_ymm, [gather_mask]
    vmovdqa element_offset_ymm, [element_offset]
    call    blowfish_expand_state_parallel_double

    pop rbp
    ret

blowfish_expand_0_state_parallel_double_wrapper:
    ; rdi -> parallel blowfish state (modified)
    ; rsi -> array of four 4 to 56 byte keys
    ; rdx:   key length
    push rbp
    mov  rbp, rsp

    vmovdqa endianness_mask_ymm, [endianness_mask]
    vmovdqa gather_mask_ymm, [gather_mask]
    vmovdqa element_offset_ymm, [element_offset]
    call    blowfish_expand_0_state_parallel_double

    pop rbp
    ret

blowfish_expand_0_state_salt_parallel_double_wrapper:
    ; rdi -> parallel blowfish state
    ; rsi -> salt
    push rbp
    mov  rbp, rsp

    vmovdqa endianness_mask_ymm, [endianness_mask]
    vmovdqa gather_mask_ymm, [gather_mask]
    vmovdqa element_offset_ymm, [element_offset]
    call    blowfish_expand_0_state_salt_parallel_double

    pop rbp
    ret