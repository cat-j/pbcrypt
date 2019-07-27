#include "bcrypt.h"

#define ENCODING_TABLE_LENGTH 64

char b64_encode_chart[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                           'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                           'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                           'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                           'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                           'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                           'w', 'x', 'y', 'z', '0', '1', '2', '3',
                           '4', '5', '6', '7', '8', '9', '+', '/'};


char get_index(char encoded_char) {
    if (encoded_char >= 'A' && encoded_char <= 'Z') {
        return encoded_char - 'A';
    } else if (encoded_char >= 'a' && encoded_char <= 'z') {
        return encoded_char - 'a' + 26;
    } else if (encoded_char >= '0' && encoded_char <= '9') {
        return encoded_char - '0' + 52;
    } else if (encoded_char == '+') {
        return 62;
    } else if (encoded_char == '/') {
        return 63;
    } else {
        return -1;
    }
}

void b64_encode(char *dst, char *src, uint64_t srcbytes) {
    uint8_t data, sextet, next_highest_bits;
    uint64_t remaining_bits = (srcbytes << 3) % 6;
    uint64_t j = 0;

    for (uint64_t i = 0; i < srcbytes; ++i) {
        data = src[i];
        switch (i % 3) {
            case 0:
                sextet = data >> 2;
                next_highest_bits = (data & 0x3) << 4;
                break;
            
            case 1:
                sextet = (data >> 4) | next_highest_bits;
                next_highest_bits = (data & 0xf) << 2;
                break;
            
            case 2:
                sextet = (data >> 6) | next_highest_bits;
                break;
            
            default:
                break;
        }

        dst[j++] = b64_encode_chart[(uint64_t) sextet];
        if (i%3 == 2) dst[j++] = b64_encode_chart[data & 0x3f];
    }

    if (remaining_bits != 0) {
        dst[j++] = b64_encode_chart[(uint64_t) next_highest_bits];
        dst[j++] = '=';
        if (remaining_bits == 2) dst[j++] = '=';
    }
}

void b64_decode(char *dst, char *src, uint64_t srcbytes) {
    char current_byte;
    unsigned char data;
    uint64_t j = 0, padding = 0, length = srcbytes;

    if (src[srcbytes-1] == '=') {
        padding++;
        
        if (src[srcbytes-2] == '=') {
            padding++;
        }
    }

    length -= padding;

    for (uint64_t i = 0; i < length; ++i) {
        current_byte = get_index(src[i]);

        switch(i%4) {
            case 0:
                data = current_byte << 2;
                break;
            
            case 1:
                data |= (current_byte >> 4) & 0x3;
                dst[j++] = data;
                data = current_byte << 4;
                break;
            
            case 2:
                data |= (current_byte >> 2) & 0xF;
                dst[j++] = data;
                data = current_byte << 6;
                break;
            
            case 3:
                data |= current_byte;
                dst[j++] = data;
                break;

            default:
                break;
        }
    }
}