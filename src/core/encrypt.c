/*
 * pbcrypt: parallel bcrypt for password cracking
 * Copyright (C) 2019  Catalina Juarros <https://github.com/cat-j>
 *
 * This file is part of pbcrypt.
 * 
 * pbcrypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * pbcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with pbcrypt.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcrypt.h"
#include "bcrypt-constants.h"
#include "print.h"

#define MAX_PASSWORD_LEN 72

int main(int argc, char const *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: encrypt <PASSWORD> <SALT> <ROUNDS_LOG>\n");
        return 1;
    }

    char password[MAX_PASSWORD_LEN+1];
    uint8_t salt[BCRYPT_SALT_BYTES+1];
    uint8_t rounds_log;
    size_t length = strlen(argv[1]);

    if (strlen(argv[2]) > MAX_PASSWORD_LEN) {
        fprintf(stderr, BOLD_RED("Error: password cannot be longer than %d bytes.\n"),
            MAX_PASSWORD_LEN);
        return 1;
    }

    strncpy((char *) &password, argv[1], MAX_PASSWORD_LEN);
    password[length] = 0;

    if (strlen(argv[2]) != BCRYPT_SALT_BYTES) {
        fprintf(stderr, BOLD_RED("Error: salt must be 16 bytes long.\n"));
        return 1;
    }

    strncpy((char *) &salt, argv[2], BCRYPT_SALT_BYTES);
    salt[BCRYPT_SALT_BYTES] = 0;
    
    rounds_log = atoi(argv[3]);

    char *encrypted = bcrypt((uint8_t *) salt, (char *) password,
        length+1, rounds_log);
    if (encrypted) {
        printf("%s\n", encrypted);
        free(encrypted);
    }

    return 0;
}
