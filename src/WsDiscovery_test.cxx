/*
 * WsDiscovery_test.cxx
 *
 *  Created on: Sep 9, 2017
 *      Author: steven
 */

#include "string.h"
#include "WsDiscovery.h"
#include "noddos.h"

int main () {
    unsigned char WsDiscoveryResponse[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:wprt=\"http://schemas.microsoft.com/windows/2006/08/wdp/print\" xmlns:wscn=\"http://schemas.microsoft.com/windows/2006/08/wdp/scan\"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action><wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To><wsa:MessageID>urn:uuid:0af48d00-a033-11b2-b522-ac1826841a46</wsa:MessageID><wsa:RelatesTo>urn:uuid:4ed84e57-4743-412a-ab29-e7887ce6f587</wsa:RelatesTo><wsd:AppSequence  InstanceId=\"271\" MessageNumber=\"10\"></wsd:AppSequence></soap:Header><soap:Body><wsd:ProbeMatches><wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:cfe92100-67c4-11d4-a45f-ac1826841a46</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device wscn:ScanDeviceType wprt:PrintDeviceType</wsd:Types><wsd:XAddrs>http://192.168.1.245:80/WSD/DEVICE</wsd:XAddrs><wsd:MetadataVersion>207</wsd:MetadataVersion></wsd:ProbeMatch></wsd:ProbeMatches></soap:Body></soap:Envelope>";
    bool testfailure = false;

    InterfaceMap ifMap;
    HostCache hC(ifMap, "", 0, "", false, true);

    auto Host = std::make_shared<WsDiscoveryHost>();

    WsDiscovery wServer(hC, 86400);
    size_t len = strlen((char *) WsDiscoveryResponse);
    if (wServer.ParseWsDiscoveryMessage(Host, WsDiscoveryResponse, len) == false) {
        testfailure = true;
    }
    if (testfailure) {
        exit(1);
    }
    exit(0);
}
