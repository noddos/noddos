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

 * MatchCondition.h
 *
 *  Created on: Mar 25, 2017
 *      Author: steven
 */

#ifndef MATCHCONDITION_H_
#define MATCHCONDITION_H_

struct MatchCondition {
public:
	std::string Key;
	std::string Value;
	bool SubsetMatch;

	MatchCondition(std::string inKey, std::string inValue, bool inSubsetMatch = false): Key{inKey}, Value{inValue}, SubsetMatch{inSubsetMatch} {}
	~MatchCondition() {
		syslog (LOG_DEBUG, "Destroying MatchCondition instance");
	}
};

#endif /* MATCHCONDITION_H_ */
