# Setup ldap-irods-auth systemd service

Copy the ldap-irods-auth binary `bin/ldap-irods-auth` to `/usr/bin/`.

Copy the systemd service `ldap-irods-auth.service` to `/usr/lib/systemd/system/`.

Create a service user `ldapirodsauth`.
```bash
sudo adduser -r -d /dev/null -s /sbin/nologin ldapirodsauth
```

Copy the ldap-irods-auth configuration `ldap-irods-auth.conf` to `/etc/ldap-irods-auth/`.
Be sure that this file must be only accessible by the `ldapirodsauth` user.

Start the service.
```bash
sudo service ldap-irods-auth start
```