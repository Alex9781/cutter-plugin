#include "pch.h"
#include "test.h"

int test_func(const int var1, const int var2)
{
	if (var1 > 10 && var2 < 10) return var1 + var2;
	if (var1 < 10 && var2 > 10) return var1 - var2;
	if (var1 == 10 && var2 == 10) return var1;
}

int test_func2(const int var1)
{
	if (var1 > 10) return var1 + 10;
	if (var1 < 10) return var1 - 10;
	if (var1 == 10) return var1;
}

int test_func3(const int var1, const int var2, const int var3)
{
	if (var1 > 10 && var2 < 10 && var2 == 10) return var1 + var2 + var3;
	if (var1 < 10 && var2 > 10 && var2 == 10) return var1 + var2 - var3;
	if (var1 == 10 && var2 == 10 && var3 == 10) return var1;
}