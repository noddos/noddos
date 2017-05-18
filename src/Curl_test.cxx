/*
 * Curl_test.cxx
 *
 *  Created on: May 17, 2017
 *      Author: steven
 */

#include <iostream>
#include <fstream>

#include <syslog.h>
#include <string.h>

#include <curl/curl.h>

#include <json.hpp>
using nlohmann::json;

static bool Debug = true;

uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile);
size_t curlwriteFunction(void *ptr, size_t size, size_t nmemb, std::string* data);

bool do_uploadstats();
bool do_uploaddevices();

int main () {
	openlog("HostCache_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
	bool testfailed = false;
	if (do_uploadstats() != true) {
		testfailed |= true;
	}
	if (do_uploaddevices() != true) {
		testfailed |= true;
	}
	if(testfailed) {
		exit(1);
    }
	exit(0);
}

bool do_uploadstats() {
	std::string filename = "tests/v1-uploadstats-20170515-021413";
	std::ifstream ifs(filename);
	json j;
	ifs >> j;
	ifs.close();
	auto r = RestApiCall ("v1/uploadstats", j, "/etc/noddos/noddosapiclient.pem", "/etc/noddos/noddosapiclient.key");
	std::cout << "Curl result: " << r << std::endl;
	return r == 201;
}

bool do_uploaddevices() {
	std::string filename = "tests/v1-uploaddevices-20170514-222118";
	std::ifstream ifs(filename);
	json j;
	ifs >> j;
	ifs.close();
	auto r = RestApiCall ("v1/uploaddevices", j, "/etc/noddos/noddosapiclient.pem", "/etc/noddos/noddosapiclient.key");
	std::cout << "Curl result: " << r << std::endl;
	return r == 201;
}


uint32_t RestApiCall (const std::string api, const json &j, const std::string ClientApiCertFile, const std::string ClientApiKeyFile) {
	std::string url = "https://api.noddos.io/" + api;

	std::string body = j.dump();
	char buf[strlen(body.c_str())+1];
	strcpy(buf, body.c_str());
	if (Debug) {
		syslog (LOG_DEBUG, "Uploading %zu bytes of data to %s", strlen(buf), url.c_str());
	}

	struct curl_slist *hlist = NULL;
	hlist = curl_slist_append(hlist, "Content-Type: application/json");
	if (hlist == NULL) {
		syslog(LOG_ERR, "Couldn't create curl header for API call to %s", api.c_str());
	}

    std::string response_string;
    std::string header_string;
    long response_code;
    double elapsed;
	auto curl = curl_easy_init();
	if (curl) {
		CURLcode ret;
		ret = curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_URL returned %d",ret);
		}
		// curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
		ret = curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_USE_SSL returned %u", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_SSLCERT, ClientApiCertFile.c_str());
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_SSLCERT returned %u", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_SSLKEY, ClientApiKeyFile.c_str());
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_SSLKEY returned %u", ret);
		}
		// ret = curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "ECDHE-RSA-AES256-GCM-SHA384");
		// if(ret) {
		//	syslog (LOG_ERR, "Curl setopt CURLOPT_SSL_CIPHER_LIST returned %d", ret);
		//}
		ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_POSTFIELDS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) strlen(buf));
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_POSTFIELDSIZE_LARGE returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_NOPROGRESS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_USERAGENT, "noddos/1.0.0");
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_USERAGENT returned %u", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_HTTPHEADER returned %d", ret);
		}
		// ret = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
		// if(ret) {
		// 	syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
		// }
		ret = curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_MAXREDIRS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 0L);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_TCP_KEEPALIVE returned %d", ret);
		}
		// ret = curl_easy_setopt(curl, CURLOPT_TCP_FASTOPEN, 1L);
		// if(ret) {
		// 	syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
		// }
		ret = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long) 5000);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_TIMEOUT_MS returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlwriteFunction);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEFUNCTION returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_WRITEDATA returned %d", ret);
		}
		ret = curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);
		if(ret) {
			syslog (LOG_ERR, "Curl setopt CURLOPT_HEADERDATA returned %d", ret);
		}
		if (false && Debug) {
			// TODO test on whether STDOUT is open for writing
			// 'always' disabled as this logs to STDOUT, which is normally closed
			ret = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		}


	    ret = curl_easy_perform(curl);
		if(ret) {
			syslog (LOG_ERR, "Curl easy_perform returned %d", ret);
		}
	    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
	    curl_slist_free_all(hlist);
	    curl_easy_cleanup(curl);
	    curl = NULL;
	    if (Debug) {
	    		syslog (LOG_DEBUG, "Upload resulted in %lu status, data %s", response_code, response_string.c_str());
	    	}
	}

    if (Debug) {
    	std::string file = api;
    	std::replace( file.begin(), file.end(), '/', '-');
    	std::time_t t = std::time(nullptr);
    	std::tm tm = *std::localtime(&t);
    	char buf[20];
    	strftime(buf,18,"%Y%m%d-%H%M%S",&tm);
    	std::string filename = "/tmp/" + file + "-" + buf;
    	std::ofstream ofs(filename);
    	if (not ofs.is_open()) {
    		syslog(LOG_WARNING, "Couldn't open %s", filename.c_str());
    	}
    	ofs << std::setw(4) << j << std::endl;
    	ofs.close();
    }
    return (uint32_t) response_code;
}

size_t curlwriteFunction(void *ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*) ptr, size * nmemb);
    return size * nmemb;
}


