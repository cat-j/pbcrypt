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