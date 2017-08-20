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

#include_directories("/home/steven/src/libtins-3.5/include")
#link_directories("/home/steven/src/libtins-3.5/lib")

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
 
add_executable(noddos noddos.cxx Host.cxx 
    HostCache.cxx SsdpServer.cxx SsdpLocation.cxx FlowTrack.cxx Config.cxx
    opensslfingerprint.cxx PacketSnoop.cxx Ipset.cxx DeviceProfile.cxx)
target_link_libraries(noddos libnetfilter_conntrack.so ssl crypto curl tins ipset)

enable_testing()

add_test (Host Host_test)
add_executable(Host_test Host_test.cxx 
    Host.cxx HostCache SsdpServer.cxx SsdpLocation.cxx
	DeviceProfile.cxx opensslfingerprint.cxx Ipset.cxx)
target_link_libraries(Host_test curl ssl crypto ipset)

add_test (HostCache Host_test)
add_executable(HostCache_test HostCache_test.cxx  Ipset.cxx
    Host.cxx HostCache SsdpServer.cxx SsdpLocation.cxx
    DeviceProfile.cxx opensslfingerprint.cxx Ipset.cxx)
target_link_libraries(HostCache_test curl ssl crypto ipset)


add_test (DeviceProfile DeviceProfile_test)
add_executable(DeviceProfile_test DeviceProfile_test.cxx 
	DeviceProfile.cxx
	FlowTrack.cxx Config.cxx HostCache.cxx Host.cxx SsdpServer.cxx
	SsdpLocation.cxx opensslfingerprint.cxx Ipset.cxx)
target_link_libraries(DeviceProfile_test curl ssl crypto netfilter_conntrack ipset)

add_test (Identifier Identifier_test)
add_executable(Identifier_test Identifier_test.cxx
	DeviceProfile.cxx Ipset.cxx)
target_link_libraries(Identifier_test ipset)

add_test (Config Config_test)
add_executable(Config_test Config_test.cxx opensslfingerprint.cxx)
target_link_libraries(Config_test curl ssl crypto)

add_test (Ipset Ipset_test)
add_executable(Ipset_test Ipset_test.cxx Ipset.cxx)
target_link_libraries(Ipset_test ipset)

add_test (SsdpServer SsdpServer_test)
add_executable(SsdpServer_test SsdpServer_test.cxx 
    HostCache.cxx Host.cxx SsdpServer.cxx SsdpLocation.cxx
    opensslfingerprint.cxx Ipset.cxx DeviceProfile.cxx)
target_link_libraries(SsdpServer_test curl ssl crypto ipset)

add_test (MacAddress MacAddress_test)
add_executable(MacAddress_test MacAddress_test.cxx)

add_test (DnsCache DnsCache_test)
add_executable(DnsCache_test DnsCache_test.cxx)

add_test (Curl Curl_test)
add_executable(Curl_test Curl_test.cxx)
target_link_libraries(Curl_test curl ssl crypto)

add_executable (PacketSnoop_test PacketSnoop_test.cxx PacketSnoop.cxx 
	HostCache.cxx Host.cxx SsdpServer.cxx SsdpLocation.cxx
    opensslfingerprint.cxx DeviceProfile.cxx Ipset.cxx)
target_link_libraries(PacketSnoop_test curl ssl crypto tins ipset)

add_test (Noddos noddos_test)
add_executable(noddos_test noddos_test.cxx)

install(TARGETS noddos RUNTIME DESTINATION usr/sbin)

