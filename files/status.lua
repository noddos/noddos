        if nixio.fs.access("/usr/lib/lua/luci/view/admin_status/clients.htm") then
                entry({"admin", "status", "clients"}, template("admin_status/clients"), _("Clients"), 3)
        end
