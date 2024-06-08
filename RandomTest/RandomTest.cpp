#include <iostream>

static int test(int var1)
{
	if (var1 > 10) return var1 + 10;
	if (var1 < 10) return var1 - 10;
	if (var1 == 10) return var1;
}

int main()
{
	int param;
	std::cin >> param;
	std::cout << test(param) << "\n";
}
