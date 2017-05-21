        if nixio.fs.access("/etc/config/noddos) then
                entry({"admin", "status", "clients"}, template("admin_status/clients"), _("Clients"), 3)
        end
