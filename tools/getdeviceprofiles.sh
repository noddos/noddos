#!/bin/bash

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

PATH=/usr/bin:/bin

WGET=`which wget`
CURL=`which curl`
BUNZIP2=`which bunzip2`
GUNZIP=`which gunzip`
BROTLI=`which brotli`
OPENSSL=`which openssl`
RM=`which rm`
CURRENTDIR=`pwd`

CERTFILE=/etc/noddos/noddosconfig.pem
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
    echo "Error getting checksum file: https://www.noddos.io/config/DeviceProfiles.json.sha256"
    cd $CWD
    exit
fi

$GETURL https://www.noddos.io/config/DeviceProfiles.json$EXT

if [ $? -gt 0 ]
then
    echo "Error getting device profiles: https://www.noddos.io/config/DeviceProfiles.json$EXT"
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
            echo "Error uncompressing device profiles in $PWD"
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

