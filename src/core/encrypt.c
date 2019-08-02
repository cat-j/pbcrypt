#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcrypt.h"
#include "bcrypt_constants.h"

int main(int argc, char const *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: encrypt <PASSWORD> <SALT> <LOG_ROUNDS>\n");
        return 1;
    }

    char password[72];
    char salt[BCRYPT_SALT_BYTES+1];
    uint64_t rounds;
    uint8_t log_rounds;

    strncpy(&password, argv[1], strlen(argv[1]));
    strncpy(&salt, argv[2], BCRYPT_SALT_BYTES);
    log_rounds = atoi(argv[3]);
    rounds = 1U << log_rounds;

    char *encrypted = bcrypt(&salt, &password, strlen(password), rounds);
    if (encrypted) {
        printf("%s\n", encrypted);
        free(encrypted);
    }

    return 0;
}
