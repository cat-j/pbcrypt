#include <stdlib.h>

#include "bcrypt-parallel.h"

p_blf_ctx *get_aligned_p_state() {
    p_blf_ctx *p_state;
    posix_memalign((void**) &p_state, 32, sizeof(p_blf_ctx));
    return p_state;
}