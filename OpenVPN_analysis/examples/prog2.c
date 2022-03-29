
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

static int main(void) {
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	//BIO *bio;
	//bio = BIO_new_connect("hostname:port");
	//if (bio == NULL) {
		// handle failed connection /
	//}



	//if(BIO_do_connect(bio) <= 0)
	//{
    		// Handle failed connection /
	//}
	return 0;
}
