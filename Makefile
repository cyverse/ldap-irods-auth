PKG=github.com/cyverse/ldap-irods-auth
VERSION=v0.1.0
GIT_COMMIT?=$(shell git rev-parse HEAD)
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS?="-X '${PKG}/commons.serviceVersion=${VERSION}' -X '${PKG}/commons.gitCommit=${GIT_COMMIT}' -X '${PKG}/commons.buildDate=${BUILD_DATE}'"
GO111MODULE=on
GOPROXY=direct
GOPATH=$(shell go env GOPATH)

.EXPORT_ALL_VARIABLES:

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -ldflags=${LDFLAGS} -o bin/ldap-irods-auth ./cmd/

.PHONY: release
release: build
	mkdir -p release
	mkdir -p release/bin
	cp bin/ldap-irods-auth release/bin
	mkdir -p release/install
	cp install/ldap-irods-auth.conf release/install
	cp install/ldap-irods-auth.service release/install
	cp install/README.md release/install
	cp Makefile.release release/Makefile
	cd release && tar zcvf ../ldap_irods_auth.tar.gz *

.PHONY: install_centos
install_centos:
	cp bin/ldap-irods-auth /usr/bin
	cp install/ldap-irods-auth.service /usr/lib/systemd/system/
	id -u ldapirodsauth || adduser -r -d /dev/null -s /sbin/nologin ldapirodsauth
	mkdir -p /etc/ldap-irods-auth
	cp install/ldap-irods-auth.conf /etc/ldap-irods-auth
	chown ldapirodsauth /etc/ldap-irods-auth/ldap-irods-auth.conf
	chmod 660 /etc/ldap-irods-auth/ldap-irods-auth.conf

.PHONY: install_ubuntu
install_ubuntu:
	cp bin/ldap-irods-auth /usr/bin
	cp install/ldap-irods-auth.service /etc/systemd/system/
	id -u ldapirodsauth || adduser --system --home /dev/null --shell /sbin/nologin ldapirodsauth
	mkdir -p /etc/ldap-irods-auth
	cp install/ldap-irods-auth.conf /etc/ldap-irods-auth
	chown ldapirodsauth /etc/ldap-irods-auth/ldap-irods-auth.conf
	chmod 660 /etc/ldap-irods-auth/ldap-irods-auth.conf

.PHONY: uninstall
uninstall:
	rm -f /usr/bin/ldap-irods-auth
	rm -f /etc/systemd/system/ldap-irods-auth.service
	rm -f /usr/lib/systemd/system/ldap-irods-auth.service
	userdel ldapirodsauth | true
	rm -rf /etc/ldap-irods-auth
