-- Copyright 2017 Steven Hessing (steven.hessing@gmail.com)
-- Licensed to the public under the Apache License 2.0.
-- /usr/lib/lua/luci/model/cbi/admin_network/noddos.lua

m = Map("noddos", translate("Client Firewall"),
    translate("Noddos controls traffic from the clients on your network to the Internet. " ..
        "This helps protect your network, the bandwidth on your Internet connection and " ..
        "the Internet"))

s = m:section(TypedSection, "noddos", translate("Server Settings"))
s.anonymous = true
s.addremove = false

s:option(Flag, "rfc1918",
    translate("Private networks"),
    translate("Report traffic to private networks (10/8, 172.16/12, 192.168/16, fd75:6b5d:352c:ed05::/64)")).default=false

s:option(Flag, "upload",
    translate("Upload anonimized traffic stats"),
    translate("Uploading your statistics helps improving device recognition " ..
        "and discovering hacked devices & botnets"))

o = s:option(DynamicList, "whitelistipv4",
    translate("Excluded IPv4 addresses"),
    translate("Don't monitor of these IPv4 addresses"))
o.optional = true
o.placeholder = "127.0.0.1 192.168.1.1"
o.delimiter = " "
o.datatype="list(ip4addr)"

o = s:option(DynamicList, "whitelistipv6",
    translate("Excluded IPv6 addresses"),
    translate("Don't monitor of these IPv6 addresses"))
o.optional = true
o.delimiter = " "
o.datatype="list(ip6addr)"

o = s:option(DynamicList, "whitelistmac",
    translate("Excluded MAC addresses"),
    translate("Don't monitor of these MAC addresses"))
o.optional = true
o.delimiter = " "
o.datatype="list(macaddr)"

return m

