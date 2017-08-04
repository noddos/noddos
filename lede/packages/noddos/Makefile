#
# Copyright (C) 2017 Steven Hessing
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=noddos
PKG_RELEASE:=1
PKG_LICENSE:=GPLv3

PKG_SOURCE_VERSION:=0.3.1
PKG_SOURCE_URL:=https://github.com/noddos/noddos/releases/download/v$(PKG_SOURCE_VERSION)/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.xz
PKG_HASH:=a90150bba4ff4af07dc2cb1bab857c87d74369816c5884fc52b917cd865aec1b

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)-$(PKG_SOURCE_VERSION)

CMAKE_INSTALL:=1
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/noddos
	SECTION:=net
	CATEGORY:=Network
	TITLE:=noddos -- device-aware cloud-powered firewall
	URL:=https://www.noddos.io/
	DEPENDS:=+libstdcpp +libnetfilter-conntrack +libcurl +libopenssl +openssl-util +ca-bundle +ca-certificates +wget +bzip2 +libtins
endef

define Package/noddos/description
Noddos discovers what devices you have in your network and tailors the firewall rules based on whitelisted flows for that device. Noddos downloads the firewall rules periodically from the cloud. In order to support creating these firewall rules, noddos can optionally upload anonimized traffic statistics for each device to the cloud.
endef

define Package/noddos/conffiles
	noddos.conf-base
	noddosconfig.pem
endef

define Package/noddos/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/noddos
	$(INSTALL_DIR) $(1)/var/lib/noddos
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/noddos $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tools/getnoddosdeviceprofiles $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tools/makenoddoscert.sh $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/noddos $(1)/etc/init.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/files/noddos.conf-base $(1)/etc/noddos
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/files/noddosconfig.pem $(1)/etc/noddos
endef

define Package/noddos/postinst
	#!/bin/sh

	echo -n "Downloading Device Profiles and checking digital signature ... "
	/usr/bin/getnoddosdeviceprofiles

	cd $(1)/etc/noddos
	# Creating a client certificate
	$(1)/usr/bin/makenoddoscert.sh

	if [ -z "$${IPKG_INSTROOT}" ]; then
		echo "Enabling rc.d symlink for noddos"
		cd /etc/rc.d
		/etc/init.d/noddos enable
	fi

	if [ ! -f /var/lib/noddos/DeviceDump.json ]; then
		echo "[]" >/var/lib/noddos/DeviceDump.json
	fi

	if [ ! -f /etc/config/noddos ]; then
		echo 'config noddos' >/etc/config/noddos
		echo "        option upload '0'" >>/etc/config/noddos
		echo "        option rfc1918 '0'" >>/etc/config/noddos
		echo "        list whitelistipv4 '127.0.0.1'" >>/etc/config/noddos
		echo "        list whitelistipv6 ''" >>/etc/config/noddos
		echo "        list whitelistmac ''" >>/etc/config/noddos
		uci commit noddos
	fi
	exit 0
endef

define Package/noddos/prerm
	#!/bin/sh
	# check if we are on real system
	if [ -z "$${IPKG_INSTROOT}" ]; then
		echo "Removing rc.d symlink for noddos"
		/etc/init.d/noddos disable
	fi
	exit 0
endef

define Package/noddos/postrm
	#!/bin/sh
	# check if we are on real system
	if [ -z "$${IPKG_INSTROOT}" ]; then
		echo "Removing noddos directories"
		rm -rf /etc/noddos /var/lib/noddos
	fi
	exit 0
endef

$(eval $(call BuildPackage,noddos))
