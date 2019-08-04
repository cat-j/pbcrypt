#ifndef _BASE64_H_
#define _BASE64_H_

#include <stddef.h>
#include <stdint.h>

int decode_base64(uint8_t *buffer, size_t len, const char *b64data);

int encode_base64(char *b64buffer, const uint8_t *data, size_t len);

size_t encoded_len(size_t len);

#endif