#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/dh.h>

int main() {
	DH *test;
	//test->pub_key = 5;
	//test->priv_key = 6;
	DH_generate_key(test);
	return 0;
}
