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

; Many functions from the loaded P implementation of bcrypt
; require some YMM registers to remain unchanged between calls,
; and calling them from C often breaks this.
; These wrappers are intended for testing the loaded P functions
; without using inline ASM or pushing YMM registers.

%include "bcrypt-macros.mac"

; Functions to be wrapped
extern blowfish_init_state_asm
extern blowfish_expand_state_asm
extern blowfish_expand_0_state_asm
extern blowfish_expand_0_state_salt_asm

; Exported functions
global blowfish_expand_state_wrapper
global blowfish_expand_0_state_wrapper
global blowfish_expand_0_state_salt_wrapper


section .data

align 32
endianness_mask: db \
0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, \
0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c, \
0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14, \
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c


section .text

; void blowfish_expand_state_wrapper(blf_ctx *state, const char *salt,
;                                    const char *key, uint16_t keybytes)

blowfish_expand_state_wrapper:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> 4 to 56 byte key
    ; rcx:   key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_function:
        call blowfish_init_state_asm
        LOAD_SALT_AND_P rdi, rsi
        call blowfish_expand_state_asm
        STORE_P rdi, rax

    .end:
        pop rbp
        ret

; void blowfish_expand_0_state_wrapper(blf_ctx *state, const char *salt,
;                                      const char *key, uint16_t keybytes)

blowfish_expand_0_state_wrapper:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> 4 to 56 byte key
    ; rcx:   key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        sub  rsp, 8

    .do_function:
        ; Save these values because blowfish_expand_state_asm would modify them
        ; rbx -> salt
        ; r12 -> key
        ; r14:   key length in bytes
        mov rbx, rsi
        mov r12, rdx
        mov r14, rcx
        
        call blowfish_init_state_asm
        LOAD_SALT_AND_P rdi, rbx
        call blowfish_expand_state_asm

        %define salt_ptr  rbx
        %define key_ptr   r12
        %define key_len   r14

        mov  rsi, key_ptr
        mov  rdx, key_len
        call blowfish_expand_0_state_asm
        STORE_P rdi, rax

    .end:
        add rsp, 8
        pop rbx
        pop rbp
        ret

; void blowfish_expand_0_state_salt_wrapper(blf_ctx *state, const char *salt,
;                                           const char *key, uint16_t keybytes)

blowfish_expand_0_state_salt_wrapper:
    ; rdi -> blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> 4 to 56 byte key
    ; rcx:   key length in bytes
    .build_frame:
        push rbp
        mov  rbp, rsp
        push rbx
        sub  rsp, 8

    .do_function:
        ; Save these values because blowfish_expand_state_asm would modify them
        ; rbx -> salt
        ; r12 -> key
        ; r14:   key length in bytes
        mov rbx, rsi
        mov r12, rdx
        mov r14, rcx
        
        call blowfish_init_state_asm
        LOAD_SALT_AND_P rdi, rbx
        call blowfish_expand_state_asm

        %define salt_ptr  rbx
        %define key_ptr   r12
        %define key_len   r14

        mov  rsi, key_ptr
        mov  rdx, key_len
        call blowfish_expand_0_state_asm

        call blowfish_expand_0_state_salt_asm
        STORE_P rdi, rax

    .end:
        add rsp, 8
        pop rbx
        pop rbp
        ret

; Helper function for correcting endianness so that tests pass.
; For internal use only.
fix_state_endianness:
    ; rdi -> blowfish state (modified)
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_function:
        STORE_P rdi, rax

        %assign i 0
        ; 4 256-element boxes => 1024 elements
        ; 4 bytes per element => 4096 bytes total
        ; 32 bytes per YMM register => 4096/32 = 128 accesses to fix all the boxes
        %rep    128
            vmovdqa ymm14, [rdi + i*YMM_SIZE]
            vpshufb ymm14, endianness_mask_ymm
            vmovdqa [rdi + i*YMM_SIZE], ymm14
            %assign i i+1
        %endrep

    .end:
        pop rbp
        ret