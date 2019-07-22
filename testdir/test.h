#ifndef _TEST_H_
#define _TEST_H_

void test_pass(const char *format, ...);

void test_fail(const char *format, ...);

void do_test(uint64_t actual, uint64_t expected, const char *test_name);

#endif