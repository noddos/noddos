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
 *      Author: Steven Hessing (steven.hessing@gmail.com)
 */

#ifndef MATCHCONDITION_H_
#define MATCHCONDITION_H_

#include <unordered_set>
#include <utility>

struct MatchCondition {
public:
	std::string Key;
	std::string Value;
	bool Debug;

	MatchCondition(const std::string inKey, const std::string inValue, const bool inDebug): Key{inKey}, Value{inValue}, Debug{inDebug} {}
	~MatchCondition() {
		DLOG_IF(INFO, Debug) << "Destroying MatchCondition instance";
	}
};

class ContainCondition {
public:
	std::string Key;
	std::unordered_set<std::string> Values;
	bool Debug;

	ContainCondition(const std::string inKey, const json j, const bool inDebug): Key{inKey}, Debug{inDebug} {
		for (auto &it: j) {
			if (it.is_string()) {
				std::string v = it;
				std::transform(v.begin(), v.end(), v.begin(), ::tolower);
				Values.insert (v);
			} else {
				LOG(ERROR) << "Contain condition " << Key << " contains a value other than a string";
			}
		}
	}
	bool contains(std::string inValue) {
		std::transform(inValue.begin(), inValue.end(), inValue.begin(), ::tolower);
		if (Values.find(inValue) == Values.end()) {
			return false;
		}
		return true;
	}
	~ContainCondition() {
		DLOG_IF(INFO, Debug) << "Destroying ContainCondition instance";
	}
};
#endif /* MATCHCONDITION_H_ */
