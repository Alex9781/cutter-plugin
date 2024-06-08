#pragma once

#define TEST_EXPORTS

#ifdef TEST_EXPORTS
#define TEST_API __declspec(dllexport)
#else
#define TEST_API __declspec(dllimport)
#endif

#include <string>

extern "C" TEST_API int test_func(const int var1, const int var2);
extern "C" TEST_API int test_func2(const int var1);
extern "C" TEST_API int test_func3(const int var1, const int var2, const int var3);