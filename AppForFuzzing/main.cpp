#include <iostream>

int test_fn(int a, int b) {
	if (a < 0) {
		printf("FAILED 1");
		return 0;
	}
	else {
		if ((a % 137 == 11) && (a % b == 8)) {
			printf("*** SUCCESS!");
			return 0x89;
		}
		else {
			printf("FAILED 2");
			return 2;
		}
	}
}

int main(int argc, char* argv[]) {
	int a, b;
	//std::cin >> a;
	a = std::atoi(argv[1]);
	b = std::atoi(argv[2]);
	test_fn(a, b);
	return 0;
}