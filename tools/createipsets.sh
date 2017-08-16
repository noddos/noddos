#!/bin/bash

SED=$(which sed)

dpfile="/var/lib/noddos/DeviceProfiles.json"

if [ $# -eq 1 ]; then
	dpfile=${1}
	if
else
	if [ ! -f ${dpfile} ]; then
		dpfile="/etc/noddos/DeviceProfiles.json"
	fi
fi

if [ ! -f ${dpfile} ]; then
	echo "Can't read ${dpfile}"
	exit
fi

sed -n 's|\s*"DeviceProfileUuid": "\w\{8\}-\(\w\{4\}\)-\(\w\{4\}\)-\(\w\{4\}\)-\(\w\{12\}\)\s*",|\1\2\3\4|p' DeviceProfiles.json | while read guid; do 
	ipset create "Nodsrc-$guid" hash:mac timeout 0
done

