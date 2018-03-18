#   Copyright 2017 Steven Hessing
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required (VERSION 2.6)

project (Noddos CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DBOOST_ERROR_CODE_HEADER_ONLY)
add_definitions(-DBOOST_SYSTEM_NO_DEPRECATED)

# The version number.
set (noddos_VERSION_MAJOR 0)
set (noddos_VERSION_MINOR 1)
 
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/noddosconfig.h.in"
  "${PROJECT_BINARY_DIR}/noddosconfig.h"
  )
 

# add the binary tree to the search path for include files
# so that we will find TutorialConfig.h
include_directories("${PROJECT_BINARY_DIR}")
 
add_executable(noddos noddos.cxx Host.cxx Mdns.cxx 
    HostCache.cxx SsdpServer.cxx FlowTrack.cxx Config.cxx
    opensslfingerprint.cxx PacketSnoop.cxx Ipset.cxx DeviceProfile.cxx WsDiscovery.cxx)
target_link_libraries(noddos libnetfilter_conntrack.so ssl crypto curl tins ipset gtest pthread yaml-cpp glog)

enable_testing()

add_executable (PacketSnoop_test PacketSnoop_test.cxx PacketSnoop.cxx 
	HostCache.cxx Host.cxx SsdpServer.cxx 
    opensslfingerprint.cxx DeviceProfile.cxx Ipset.cxx)
target_link_libraries(PacketSnoop_test curl ssl crypto tins ipset gtest pthread yaml-cpp glog)

add_test (Noddos noddos_test)
add_executable(noddos_test noddos_test.cxx Host.cxx Mdns.cxx 
    HostCache.cxx SsdpServer.cxx FlowTrack.cxx Config.cxx
    opensslfingerprint.cxx PacketSnoop.cxx Ipset.cxx DeviceProfile.cxx
    WsDiscovery.cxx)
target_link_libraries(noddos_test curl ssl crypto ipset tins yaml-cpp gtest
    pthread libnetfilter_conntrack.so curl pthread yaml-cpp glog)

install(TARGETS noddos RUNTIME DESTINATION usr/sbin)

