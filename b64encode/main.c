#include <stdio.h>
#include <string.h>

#include "../src/base64.h"

int main(int argc, char const *argv[]) {
    // size_t len = encoded_len(strlen(argv[1]));
    // printf("%d\n", len);
    char encoded[256];
    
    if (encode_base64(&encoded, argv[1], strlen(argv[1])))
        return 1;

    printf("%s\n", encoded);
    return 0;
}
