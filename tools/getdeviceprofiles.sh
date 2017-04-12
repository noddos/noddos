#!/bin/bash

# Copyright 2017 Steven Hessing
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

PATH=/usr/bin:/bin

WGET=`which wget`
CURL=`which curl`
BUNZIP2=`which bunzip2`
GUNZIP=`which gunzip`
BROTLI=`which brotli`
OPENSSL=`which openssl`
RM=`which rm`
CURRENTDIR=`pwd`

CERTFILE=/etc/noddos/noddosconfig.crt
OUTDIR=/var/lib/noddos
while [[ $# -gt 1 ]]
do
    option="$1"

    case $option in
        -c|--certificate)
            CERTFILE="$2"
            shift # past argument
        ;;
        -d|--directory)
            OUTDIR="$2"
            shift # past argument
        ;;
        *)
            echo "Unknown command line option: $option"
            exit
        ;;
    esac
    shift
done

if [ ! -f $CERTFILE ]
then
    print "Can't read certfile: $CERTFILE"
    exit
fi

UNZIP=none
EXT=
if [ "$BROTLI" != "" ]
then
    UNZIP=$BROTLI
    EXT=.brotli
else
    if [ -x $BUNZIP2 ]
    then
        UNZIP="$BUNZIP2 --keep"
        EXT=.bz2
    else
        if [ -x $GUNZIP ]
        then
            UNZIP="$GUNZIP --keep"
            EXT=.gz
        fi
    fi
fi

if [ "$OPENSSL" == "" ]
then
    echo "$OPENSSL command not found"
    exit
fi

# wget is preferred because it does conditional gets
# That's also why we don't delete the downloaded file
if [ "$WGET" != "" ]
then
    GETURL="$WGET --quiet --timestamping"
else
    if [ "$CURL" != "" ]
    then
        GETURL="$CURL -s -O"
    else
        print "No wget or curl found"
        exit
    fi
fi

if [ ! -d "$OUTDIR/tmp" ] 
then
    mkdir $OUTDIR/tmp
    if [ $? -gt 0 ]
    then
        print "Couldn't create tmp dir in $OUTDIR"
        exit
    fi
fi

cd $OUTDIR/tmp

$GETURL https://www.noddos.io/config/DeviceProfiles.json.sha256

if [ $? -gt 0 ]
then
    echo "Error getting checksum file"
    cd $CWD
    exit
fi

$GETURL https://www.noddos.io/config/DeviceProfiles.json$EXT

if [ $? -gt 0 ]
then
    echo "Error getting device profiles"
    cd $CWD
    exit
fi

if [ "$EXT" != "none" ]
then
    if [ -f DeviceProfiles.json ]
    then
        $RM DeviceProfiles.json
    fi
    if [ "$EXT" == ".brotli" ]
    then
        $UNZIP --decompress --input DeviceProfiles.json$EXT --output DeviceProfiles.json
        if [ $? -gt 0 ]
        then
            echo "Error uncompressing device profiles"
            cd $CWD
            exit
        fi
    else
        $UNZIP DeviceProfiles.json$EXT
        if [ $? -gt 0 ]
        then
            echo "Error uncompressing device profiles"
            cd $CWD
            exit
        fi
    fi
fi

$OPENSSL dgst -sha256 \
    -verify  <($OPENSSL x509 -in $CERTFILE  -pubkey -noout) \
    -signature DeviceProfiles.json.sha256 DeviceProfiles.json

if [ $? -gt 0 ]
then
    echo "Error verifying checksum!"
    cd $CWD
    exit
fi

cp DeviceProfiles.json $OUTDIR
cd $CWD

