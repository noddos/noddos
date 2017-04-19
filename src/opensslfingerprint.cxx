/*
   Copyright 2017 Steven Hessing

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    * file: opensslfingerprint.cxx
    * author: steven
    * date: 04/01/2017
*/

#include <iostream>
#include <memory>
#include <cstdio>

#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <syslog.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bio.h>


std::string getCertFingerprint(std::string certfile) {

	// checks file
	struct stat sb;
	if ((stat(certfile.c_str(), &sb)) == -1)
	{
		syslog(LOG_CRIT, "Can't stat() %s", certfile.c_str());
		return "";
	};
	ssize_t len = (sb.st_size * 2);

	// allocates memory
	unsigned char * buff;
	if (not(buff = (unsigned char *) malloc(len))) {
		fprintf(stderr, "peminfo: out of virtual memory\n");
		return"";
	};

	// opens file for reading
	int fd;
	if ((fd = open(certfile.c_str(), O_RDONLY)) == -1) {
		syslog (LOG_CRIT, "open() for %s", certfile.c_str());
		free(buff);
		return "";
	};

	// reads file
	if ((len = read(fd, buff, len)) == -1) {
		syslog (LOG_CRIT, "read() of %s", certfile.c_str());
		free(buff);
		return "";
	};

	// closes file
	close(fd);

	// initialize OpenSSL
	SSL_load_error_strings();
	SSL_library_init();

	// creates BIO buffer
	BIO * bio = BIO_new_mem_buf(buff, len);

	// decodes buffer
	X509 * x;
	if (not(x = PEM_read_bio_X509(bio, NULL, 0L, NULL))) {
		unsigned	err;
		char		errmsg[1024];
		while((err = ERR_get_error())) {
			errmsg[1023] = '\0';
			ERR_error_string_n(err, errmsg, 1023);
			syslog (LOG_ERR, "openssl %s\n", errmsg);
		};
		BIO_free(bio);
		free(buff);
		return "";
	};

    printf("name:      %s\n",    x->name);
    printf("serial:    ");
    printf("%02X", x->cert_info->serialNumber->data[0]);
    for(int pos = 1; pos < x->cert_info->serialNumber->length; pos++) {
        printf(":%02X", x->cert_info->serialNumber->data[pos]);
    }
    printf("\n");

	// calculate fingerprint
	const EVP_MD * digest = EVP_get_digestbyname("sha1");

	unsigned int    n;
	unsigned char   md[EVP_MAX_MD_SIZE];

	X509_digest(x, digest, md, &n);

	char fpbuf[64];
	for(int pos = 0; pos < 19; pos++) {
	    snprintf(&fpbuf[pos * 3], 4, "%02x:", md[pos]);
    }
	snprintf(&fpbuf[57], 3, "%02x", md[19]);

    printf("Fingerprint: ");
	for(int pos = 0; pos < 19; pos++) {
	    printf("%02x:", md[pos]);
    }
    printf("%02x\n", md[19]);

	std::string fp = fpbuf;
	// frees memory
	BIO_free(bio);
	free(buff);

	return fp;
}
