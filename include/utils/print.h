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

#ifndef _PRINT_H_
#define _PRINT_H_

#include <stddef.h>
#include <stdint.h>

#define RED(x)          "\033[0;31m"x"\033[0m"
#define GREEN(x)        "\033[0;32m"x"\033[0m"
#define YELLOW(x)       "\033[0;33m"x"\033[0m"
#define BLUE(x)         "\033[0;34m"x"\033[0m"
#define MAGENTA(x)      "\033[0;35m"x"\033[0m"
#define CYAN(x)         "\033[0;36m"x"\033[0m"

#define BOLD_RED(x)     "\033[1;31m"x"\033[0m"
#define BOLD_GREEN(x)   "\033[1;32m"x"\033[0m"
#define BOLD_YELLOW(x)  "\033[1;33m"x"\033[0m"
#define BOLD_BLUE(x)    "\033[1;34m"x"\033[0m"
#define BOLD_MAGENTA(x) "\033[1;35m"x"\033[0m"
#define BOLD_CYAN(x)    "\033[1;36m"x"\033[0m"

void print_hex(uint8_t *buf, size_t length);

#endif