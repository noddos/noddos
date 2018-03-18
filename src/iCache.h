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

 * iCache.h
 *
 *  Created on: Mar 22, 2017
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef ICACHE_H_
#define ICACHE_H_

#include <ctime>

class iCache {
protected:
	time_t Expires;
	time_t FirstSeen, LastSeen, LastModified;
public:
	virtual time_t setExpiration (uint32_t inTtl) = 0;
	virtual time_t getExpiration () = 0;
	virtual bool isExpired () = 0;
	bool Fresh(uint32_t time_interval) { return iCache::LastSeen > (time(nullptr) - time_interval); }
	virtual uint32_t Prune(bool Force) = 0;
	virtual ~iCache() {};
};

#endif /* ICACHE_H_ */
