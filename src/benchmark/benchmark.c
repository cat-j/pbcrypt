#include <malloc.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

#include "instructions.h"

#define ITERATIONS 4294967296

uint64_t measure(void (*benchmark_func)(uint64_t),
                 uint64_t iterations)
{
    uint64_t start_time = clock();
    benchmark_func(iterations);
    uint64_t end_time = clock();
    return end_time-start_time;
}

uint64_t measure_rw(void (*benchmark_func)(uint64_t, uint64_t *),
                    uint64_t iterations)
{
    uint64_t data;
    uint64_t start_time = clock();
    benchmark_func(iterations, &data);
    uint64_t end_time = clock();
    return end_time-start_time;
}

/*
 * Usage: ./build/benchmark "<RESULTS_FILENAME>"
 */
int main(int argc, char const *argv[]) {
    // Initialise file for measurements if needed
    int write_header = 0;

    if (access(argv[1], F_OK) == -1) {
        // File doesn't exist, header must be written
        write_header = 1;
    }

    FILE *r_stream = fopen(argv[1], "a");

    if (write_header) {
        fprintf(r_stream, "read;write;vpextrd;pextrq;pinsrq;vpermq;vpshufb;bswap;iterations\n");
    }

    uint64_t t_read = measure_rw(benchmark_read, ITERATIONS);
    uint64_t t_write = measure_rw(benchmark_write, ITERATIONS);
    uint64_t t_vpextrd = measure(benchmark_vpextrd, ITERATIONS);
    uint64_t t_pextrq = measure(benchmark_pextrq, ITERATIONS);
    uint64_t t_pinsrq = measure(benchmark_pinsrq, ITERATIONS);
    uint64_t t_vpermq = measure(benchmark_vpermq, ITERATIONS);
    uint64_t t_vpshufb = measure(benchmark_vpshufb, ITERATIONS);
    uint64_t t_bswap = measure(benchmark_bswap, ITERATIONS);

    fprintf(r_stream,
        "%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64"\n",
        t_read, t_write, t_vpextrd, t_pextrq, t_pinsrq, t_vpermq, t_vpshufb, t_bswap, ITERATIONS);

    fclose(r_stream);

    return 0;
}