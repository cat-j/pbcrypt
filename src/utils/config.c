/*
 * pbcrypt: parallel bcrypt for password cracking
 * Copyright (C) 2019  Catalina Juarros (catalinajuarros@protonmail.com)
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

#include "cracker-errors.h"
#include "print.h"

extern int measure;
extern char *results_filename;

int load_config() {
    FILE *fp = fopen("./config-cracker", "r");

    if (fp) {
        char buf1[256];

        fscanf(fp, "%s %d", buf1, &measure);
        results_filename = getenv("RESULTS_FILENAME");

        // If measuring performance, the file to write to
        // must be opened properly.
        if (measure && !results_filename) {
            fclose(fp);
            return ERR_RESULTS_FNAME;
        }

        fclose(fp);
    } else {
        return ERR_OPEN_CONFIG;
    }

    return 0;
}