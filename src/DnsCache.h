/*
 * DnsCache.h
 *
 *  Created on: Jun 3, 2017
 *      Author: steven
 */

#ifndef DNSCACHE_H_
#define DNSCACHE_H_

#include "boost/asio.hpp"

typedef std::map<std::string, time_t> QueryCache;
typedef std::map<boost::asio::ip::address_v4, std::unordered_set<std::map<std::string,time_t>>>;


class DnsCache {
private:
	QueryCache qC;
	std::map

public:
	DnsCache();
	~DnsCache();
};

#endif /* DNSCACHE_H_ */
