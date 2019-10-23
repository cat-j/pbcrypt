global benchmark_read
global benchmark_write
global benchmark_vpextrd
global benchmark_pextrq
global benchmark_vpextrq
global benchmark_pinsrq
global benchmark_vpinsrq
global benchmark_vpermq
global benchmark_vpshufb
global benchmark_bswap


section .data

align 32
endianness_mask: db \
0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, \
0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c, \
0x13, 0x12, 0x11, 0x10, 0x17, 0x16, 0x15, 0x14, \
0x1b, 0x1a, 0x19, 0x18, 0x1f, 0x1e, 0x1d, 0x1c


section .text

; void benchmark_read(uint64_t iterations, uint64_t *data)

benchmark_read:
    ; rdi: iterations
    ; rsi: pointer to read from
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp rcx, rdi
            je  .end
            mov rdx, [rsi]
            inc rcx
            jmp .execute

    .end:
        pop rbp
        ret

; void benchmark_write(uint64_t iterations, uint64_t *data)

benchmark_write:
    ; rdi: iterations
    ; rsi: pointer to write to
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp rcx, rdi
            je  .end
            mov [rsi], rdx
            inc rcx
            jmp .execute

    .end:
        pop rbp
        ret

; void benchmark_vpextrd(uint64_t iterations)

benchmark_vpextrd:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp     rcx, rdi
            je      .end
            vpextrd rdx, xmm0, 0
            inc     rcx
            jmp     .execute

    .end:
        pop rbp
        ret

; void benchmark_pextrq(uint64_t iterations)

benchmark_pextrq:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp    rcx, rdi
            je     .end
            pextrq rdx, xmm0, 0
            inc    rcx
            jmp    .execute

    .end:
        pop rbp
        ret

; void benchmark_vpextrq(uint64_t iterations)

benchmark_vpextrq:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp     rcx, rdi
            je      .end
            vpextrq rdx, xmm0, 0
            inc     rcx
            jmp     .execute

    .end:
        pop rbp
        ret

; void benchmark_pinsrq(uint64_t iterations)

benchmark_pinsrq:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp    rcx, rdi
            je     .end
            pinsrq xmm0, rdx, 0
            inc    rcx
            jmp    .execute

    .end:
        pop rbp
        ret

; void benchmark_vpinsrq(uint64_t iterations)

benchmark_vpinsrq:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp     rcx, rdi
            je      .end
            vpinsrq xmm0, xmm0, rdx, 0
            inc     rcx
            jmp     .execute

    .end:
        pop rbp
        ret

; void benchmark_vpermq(uint64_t iterations)

benchmark_vpermq:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp    rcx, rdi
            je     .end
            vpermq ymm0, ymm0, 0x4e
            inc    rcx
            jmp    .execute

    .end:
        pop rbp
        ret

; void benchmark_vpshufb(uint64_t iterations)

benchmark_vpshufb:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        vmovdqa ymm1, [endianness_mask]
        xor rcx, rcx

        .execute:
            cmp     rcx, rdi
            je      .end
            vpshufb ymm0, ymm1
            inc     rcx
            jmp     .execute

    .end:
        pop rbp
        ret

; void benchmark_bswap(uint64_t iterations)

benchmark_bswap:
    ; rdi: iterations
    .build_frame:
        push rbp
        mov  rbp, rsp

    .do_benchmark:
        xor rcx, rcx

        .execute:
            cmp    rcx, rdi
            je     .end
            bswap  edx
            inc    rcx
            jmp    .execute

    .end:
        pop rbp
        ret