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

openssl req \
    -x509 \
    -newkey rsa:4096 \
    -keyout noddosapiclient.pem \
    -out noddosapiclient.pem \
    -days 3650 \
    -nodes \
    -subj "/C=US/ST=noddosclientcert/L=Somewhere/O=Noddos/CN=client@noddos.io"  

fingerprint=$(openssl x509 -noout -in noddosapiclient.pem -fingerprint 2>/dev/null | \
     sed 's|SHA1 Fingerprint=||' | tr -d ':')

echo "Certificate fingerprint " $fingerprint
