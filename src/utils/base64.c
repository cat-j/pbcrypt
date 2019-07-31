/*
 * Copyright (c) 2014 Ted Unangst <tedu@openbsd.org>
 * Copyright (c) 1997 Niels Provos <provos@umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "base64.h"

static const uint8_t Base64Code[] =
"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static const uint8_t index_64[128] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 0, 1, 54, 55,
    56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
    255, 255, 255, 255, 255, 2, 3, 4, 5, 6,
    7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    255, 255, 255, 255, 255, 255, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 255, 255, 255, 255, 255
};
#define CHAR64(c)  ( (c) > 127 ? 255 : index_64[(c)])

/*
 * read buflen (after decoding) bytes of data from b64data
 */
int decode_base64(uint8_t *buffer, size_t len, const char *b64data) {
    uint8_t *bp = buffer;
    const uint8_t *p = b64data;
    uint8_t c1, c2, c3, c4;

    while (bp < buffer + len) {
        c1 = CHAR64(*p);
        /* Invalid data */
        if (c1 == 255)
            return -1;

        c2 = CHAR64(*(p + 1));
        if (c2 == 255)
            return -1;

        *bp++ = (c1 << 2) | ((c2 & 0x30) >> 4);
        if (bp >= buffer + len)
            break;

        c3 = CHAR64(*(p + 2));
        if (c3 == 255)
            return -1;

        *bp++ = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);
        if (bp >= buffer + len)
            break;

        c4 = CHAR64(*(p + 3));
        if (c4 == 255)
            return -1;
        *bp++ = ((c3 & 0x03) << 6) | c4;

        p += 4;
    }
    return 0;
}

/*
 * Turn len bytes of data into base64 encoded data.
 * This works without = padding.
 */
int encode_base64(char *b64buffer, const uint8_t *data, size_t len) {
    uint8_t *bp = b64buffer;
    const uint8_t *p = data;
    uint8_t c1, c2;

    while (p < data + len) {
        c1 = *p++;
        *bp++ = Base64Code[(c1 >> 2)];
        c1 = (c1 & 0x03) << 4;
        if (p >= data + len) {
            *bp++ = Base64Code[c1];
            break;
        }
        c2 = *p++;
        c1 |= (c2 >> 4) & 0x0f;
        *bp++ = Base64Code[c1];
        c1 = (c2 & 0x0f) << 2;
        if (p >= data + len) {
            *bp++ = Base64Code[c1];
            break;
        }
        c2 = *p++;
        c1 |= (c2 >> 6) & 0x03;
        *bp++ = Base64Code[c1];
        *bp++ = Base64Code[c2 & 0x3f];
    }
    *bp = '\0';
    return 0;
}

size_t encoded_len(size_t len) {
    size_t bits = len << 3;
    if (bits % 6 == 0) {
        return bits / 6;
    } else {
        return bits / 6 + 1;
    }
}