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

 * DeviceInfoSource.h
 *
 *  Created on: Mar 12, 2017
 *      Author: steven
 */

#ifndef IDEVICEINFOSOURCE_H_
#define IDEVICEINFOSOURCE_H_

class iDeviceInfoSource {
	public:
		virtual int GetFileHandle() = 0;
		virtual bool ProcessEvent(struct epoll_event &event) = 0;
		virtual int Open(std::string input, uint32_t inExpiration) = 0;
		virtual bool Close() = 0;
		virtual ~iDeviceInfoSource(){};
};

#endif /* IDEVICEINFOSOURCE_H_ */
