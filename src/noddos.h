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

 * noddos.h
 *
 *  Created on: Mar 11, 2017
 *      Author: steven
 */

#ifndef NODDOS_H_
#define NODDOS_H_

#define FLOWDEFAULTEXPIRATION 14400

enum struct ConfidenceLevel : int { None, none, NONE, Low, low, LOW, Medium, medium, MEDIUM, High, high, HIGH };

size_t curlwriteFunction(void *ptr, size_t size, size_t nmemb, std::string* data);

#endif /* NODDOS_H_ */
