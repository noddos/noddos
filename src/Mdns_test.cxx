/*
 * WsDiscovery_test.cxx
 *
 *  Created on: Sep 9, 2017
 *      Author: steven
 */

#include <syslog.h>

#include "Mdns.h"
#include "noddos.h"

int main() {
    openlog("Config_test", LOG_NOWAIT | LOG_PID | LOG_PERROR, LOG_UUCP);
    bool testfailure = false;
    std::string msg = "^txtvers=1^priority=30^ty=EPSON XP-410 Series^usb_MFG=EPSON^usb_MDL=XP-410 Series^product=(EPSON XP-410 Series)^pdl=application/octet-stream,image/urf,image/jpeg^rp=ipp/print^qtotal=1&adminurl=http://EPSON410.local.:80/PRESENTATION/BONJOUR^note=^Color=T^Duplex=F^Fax=F^Scan=T^URF=CP1,MT1-3-8-10-11-12,PQ4-5,OB9,OFU0,RS360,SRGB24,W8,IS1,V1.2^UUID=cfe92100-67c4-11d4-a45f-ac1826841a46";
    msg[0] = 9;
    msg[10] = 11;
    msg[22] = 22;
    msg[45] = 13;
    msg[59] = 21;
    msg[81] = 29;
    msg[111] = 49;
    msg[161] = 12;
    msg[174] = 8;
    msg[183] = 55;
    msg[239] = 5;
    msg[245] = 7;
    msg[253] = 8;
    msg[262] = 5;
    msg[268] = 6;
    msg[275] = 64;
    msg[340] = 41;

    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, 14400, "", false, true);

    auto Host = std::make_shared<MdnsHost>();

    Mdns m(hC, 86400);
    m.parseTxtRr(Host, msg);

    if (Host->Manufacturer != "EPSON") {
        testfailure = true;
    }
    if (Host->ModelName != "XP-410 Series") {
        testfailure = true;
    }
    if (Host->DeviceUrl != "http://EPSON410.local.:80/PRESENTATION/BONJOUR") {
        testfailure = true;
    }
    if (testfailure) {
        exit(1);
    }
    exit (0);
}
