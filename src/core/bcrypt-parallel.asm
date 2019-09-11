%include "bcrypt-macros.mac"

; variables
extern initstate_asm

; exported functions for bcrypt implementation
global blowfish_parallelise_state
global blowfish_init_state_parallel
global blowfish_expand_state_parallel


section .data

align 32
endianness_mask: db \
0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, \
0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c, \
0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14, \
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c

align 32
element_offset: dd 0x0, 0x1, 0x2, 0x3


section .text

; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ;;;;;;;;; FUNCTIONS ;;;;;;;;;;
; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; WARNING: THIS DOES NOT FOLLOW CDECL. For internal use only.
blowfish_encipher_parallel:
    ; rdi -> parallel blowfish state (4 keys)
    ; ymm0: | 4 Xls | 4 Xrs |
    ; ymm3: | 4 s0s | 4 s1s |
    ; ymm5: | 4 s2s | 4 s3s |
    .build_frame:
        push rbp
        mov  rbp, rsp
    
    .separate_xl_xr:
        %define x_l   xmm0
        %define x_r   xmm2
        %define p_y   ymm4
        %define p_l   xmm4
        %define p_r   xmm6
        %define mask  xmm7
        %define f_out xmm8
        %define tmp1  xmm9
        %define tmp2  xmm10
        %define mask  xmm11

        ROTATE_128(ymm0)
        movdqa x_r, xmm0 ; x_r = 4 Xrs
        ROTATE_128(ymm0) ; x_l = 4 Xls
    
    .do_encipher:
        vmovdqa p_y, [rdi + P_BLF_CTX_P_OFFSET] ; | 4 P[0]s | 4 P[1]s |
        ROTATE_128(p_y)
        movdqa  p_r, p_l ; p_r = 4 P[1]s
        ROTATE_128(p_y)  ; p_l = 4 P[0]s

        ; macro parameters: s, p[n], i, j, F outputs, tmp1, tmp2, mask
        pxor x_l, p_l ; Xl <- Xl ^ P[0]
        BLOWFISH_ROUND_XMM rdi, p_r, x_r, x_l, f_out, tmp1, tmp2, mask

        ; n is even and ranges 2 to 14
        ; n+1 is odd and ranges 3 to 15
        ; %rep 7
        ; %endrep

    .end:
        pop rbp
        ret

; void blowfish_parallelise_state(p_blf_ctx *state, blf_ctx *src)

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
        %rep    1024
            vpbroadcastd parallel_elements_x, [rsi + i*S_ELEMENT_MEMORY_SIZE]
            vmovdqa      [rdi + i*16], parallel_elements_x
            %assign i i+1
        %endrep

    .copy_P_array:
        %rep 18
            vpbroadcastd parallel_elements_x, [rsi + i*S_ELEMENT_MEMORY_SIZE]
            vmovdqa      [rdi + i*16], parallel_elements_x
            %assign i i+1
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
    
    .copy_S_boxes:
        %define eight_elements ymm1
        ; 4 1024-element boxes => 4096 elements
        ; 8 elements per YMM => 4096/8 = 512 accesses
        %assign i 0
        %rep    512
            vmovdqa eight_elements, [rsi + i*YMM_SIZE]
            vmovdqa [rdi + i*YMM_SIZE], eight_elements
            %assign i i+1
        %endrep

    .copy_P_array:
        ; 72 P-elements
        ; 8 elements per YMM => 72/8 = 9 accesses
        %rep 9
            vmovdqa eight_elements, [rsi + i*YMM_SIZE]
            vmovdqa [rdi + i*YMM_SIZE], eight_elements
            %assign i i+1
        %endrep

    .end:
        pop rbp
        ret

; void blowfish_expand_state_parallel(p_blf_ctx *state, const char *salt,
;                                     const char *keys, uint64_t keybytes)

blowfish_expand_state_parallel:
    ; rdi -> parallel blowfish state (modified)
    ; rsi -> 128-bit salt
    ; rdx -> array of four 4 to 56 byte keys
    ; rcx:   key length
    .build_frame:
        push rbp
        mov  rbp, rsp

    .p_array_keys:
        ; read four bytes from each key and XOR
        %define key_data     xmm1
        %define key_data_ctr r8
        %define key_ptr      rdx
        %define key_len      rcx
        %define loop_ctr     r9
        %define tmp          xmm2

        ; initialise registers
        xor loop_ctr, loop_ctr

        %assign i 0
        %rep 18
            xor loop_ctr, loop_ctr
            READ_4_KEY_BYTES_PARALLEL key_data, key_data_ctr, key_ptr, \
                key_len, loop_ctr, i
            pxor   key_data, [rdi + P_BLF_CTX_P_OFFSET + i*4*P_VALUE_MEMORY_SIZE]
            movdqa [rdi + P_BLF_CTX_P_OFFSET + i*4*P_VALUE_MEMORY_SIZE], key_data
            %assign i i+1
        %endrep

    .p_array_salt:
        %define data      ymm0
        %define salt_0    xmm3
        %define salt_1    xmm4
        %define salt_2    xmm5
        %define salt_3    xmm6
        %define salt_0_1  ymm3
        %define salt_2_3  ymm5

        ; TODO: remove this and write a test wrapper after moving it to hashpass
        vmovdqa endianness_mask_ymm, [endianness_mask]

        ; copy each 32-bit block four times
        vpbroadcastd salt_0, [rsi]
        vpbroadcastd salt_1, [rsi + 4]
        vpbroadcastd salt_2, [rsi + 8]
        vpbroadcastd salt_3, [rsi + 12]

        ; initialise variables
        vpxor       data, data ; 0
        vinserti128 salt_0_1, salt_0, 0
        vinserti128 salt_0_1, salt_1, 1
        vinserti128 salt_2_3, salt_2, 0
        vinserti128 salt_2_3, salt_3, 1
        vpshufb     salt_0_1, endianness_mask_ymm
        vpshufb     salt_2_3, endianness_mask_ymm

        ; actual enciphering
        vpxor   data, salt_0_1
        call    blowfish_encipher_parallel
        vpxor   data, [rdi + P_BLF_CTX_P_OFFSET]
        vmovdqa [rdi + P_BLF_CTX_P_OFFSET], data

        vpxor   data, salt_2_3
        call    blowfish_encipher_parallel
        vpxor   data, [rdi + P_BLF_CTX_P_OFFSET]
        vmovdqa [rdi + P_BLF_CTX_P_OFFSET + 32], data

    .end:
        pop rbp
        ret