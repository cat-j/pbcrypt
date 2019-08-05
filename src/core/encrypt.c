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
    size_t length = strlen(argv[1]);

    strncpy((char *) &password, argv[1], length);
    password[length] = 0;

    strncpy((char *) &salt, argv[2], BCRYPT_SALT_BYTES);
    salt[BCRYPT_SALT_BYTES] = 0;
    
    log_rounds = atoi(argv[3]);
    rounds = 1U << log_rounds;

    printf("Password: %s\n", password);
    printf("Rounds: %lu\n", rounds);
    printf("Length: %lu\n", length);

    char *encrypted = bcrypt((char *) &salt, (char *) &password,
        length, rounds);
    if (encrypted) {
        printf("%s\n", encrypted);
        free(encrypted);
    }

    return 0;
}
