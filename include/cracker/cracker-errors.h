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

#ifndef _BCRYPT_ERRORS_H_
#define _BCRYPT_ERRORS_H_

#define ERR_OPEN_CONFIG   0x10010
#define ERR_RESULTS_FNAME 0x10020

#define ERR_RECORD_LEN    0x20010
#define ERR_RECORD_FORMAT 0x20020
#define ERR_VERSION       0x20030
#define ERR_ROUNDS        0x20040
#define ERR_BASE64        0x20050

#define ERR_ARGS          0x30010
#define ERR_N_PASSWORDS   0x30020
#define ERR_OPEN_FILE     0x30030
#define ERR_FILE_DATA     0x30040

#define ERR_BAD_SALT      0x40010
#define ERR_BAD_KEY       0x40020
#define ERR_BAD_HASH      0x40030
#define ERR_SALT_LEN      0x40040

#endif