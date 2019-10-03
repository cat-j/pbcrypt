#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"

int main(int argc, char const *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: encrypt <PASSWORD> <SALT> <LOG_ROUNDS>\n");
        return 1;
    }

    char password[72];
    uint8_t salt[BCRYPT_SALT_BYTES+1];
    uint8_t log_rounds;
    size_t length = strlen(argv[1]);

    strncpy((char *) &password, argv[1], 72);
    password[length] = 0;

    strncpy((char *) &salt, argv[2], BCRYPT_SALT_BYTES);
    salt[BCRYPT_SALT_BYTES] = 0;
    
    log_rounds = atoi(argv[3]);

    printf("Password: %s\n", password);
    printf("Rounds: %lu\n", 1L << log_rounds);
    printf("Length: %lu\n", length);

    char *encrypted = bcrypt((uint8_t *) &salt, (char *) &password,
        length+1, log_rounds);
    if (encrypted) {
        printf("%s\n", encrypted);
        free(encrypted);
    }

    return 0;
}
