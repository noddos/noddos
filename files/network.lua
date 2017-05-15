        if nixio.fs.access("/etc/config/noddos") then
            page = entry({"admin", "network", "noddos"}, cbi("admin_network/noddos"), nil)
            page.target = cbi("admin_network/noddos")
            page.title = _("Client Firewall")
            page.order = 55
            page.leaf = true
        end

