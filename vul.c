// This file is vulnerable with CVE-2016-6303
// this vulnerability was last present with OpenSSL 1.0.2h and fixed in its successor 1.1.0
// 
#include <stdio.h>
#include <stdlib.h>
#include <openssl/mdc2.h>
#include <string.h>

int main() {
	unsigned char md[MDC2_DIGEST_LENGTH];
    	int i;
    	MDC2_CTX c;
    	static char *text = "Now is the time for all ";

    	MDC2_Init(&c);
    	MDC2_Update(&c, text, strlen(text));
    	MDC2_Final(&(md[0]), &c);

    	for (i = 0; i < MDC2_DIGEST_LENGTH; i++)
        	printf("%02X", md[i]);
    	printf("\n");
	return 0;
}
