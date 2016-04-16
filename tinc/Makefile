#
# Copyright (C) 2007-2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tinc
PKG_VERSION:=1.1pre11
PKG_RELEASE:=20160415

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE).tar.gz
PKG_SOURCE_URL:=http://10.3.3.2/packages 
PKG_MD5SUM:=9e7b53af8982f10117c8a014aa3c1366
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/tinc
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+kmod-tun +TINC_ZLIB:zlib +TINC_LZO:liblzo +!TINC_NOLEGACY:libopenssl +TINC_READLINE:libreadline +TINC_CURSES:libncurses
  TITLE:=VPN tunneling daemon
  URL:=http://www.tinc-vpn.org/
  SUBMENU:=VPN
  MENU:=1
endef

define Package/tinc/description
  tinc is a Virtual Private Network (VPN) daemon that uses tunnelling and
  encryption to create a secure private network between hosts on the Internet.
  ob.scu.red patches
endef

define Package/tinc/config
  config TINC_ZLIB
    bool "Enable zlib (compression levels 0-9)"
    depends on PACKAGE_tinc
    default y

  config TINC_LZO
    bool "Enable lzo (compression levels 10-11)"
    depends on PACKAGE_tinc
    default y

  config TINC_READLINE
    bool "Enable readline library use"
    depends on PACKAGE_tinc
    default n

  config TINC_CURSES
    bool "Enable curses in tinc"
    depends on PACKAGE_tinc
    default n

  config TINC_NOLEGACY
    bool "Disable the legacy protocol (removes openssl dependency)"
    depends on PACKAGE_tinc
    default y

  config TINC_NOCTL
    bool "Only provide core daemon without control interface (to save space)"
    depends on PACKAGE_tinc
    default n
endef

TARGET_CFLAGS += -std=gnu99

CONFIGURE_ARGS += \
	--with-kernel="$(LINUX_DIR)"

ifneq ($(CONFIG_TINC_ZLIB),y)
	CONFIGURE_ARGS += \
	--disable-zlib
else
	CONFIGURE_ARGS += \
	--with-zlib="$(STAGING_DIR)/usr"
endif

ifneq ($(CONFIG_TINC_LZO),y)
	CONFIGURE_ARGS += \
	--disable-lzo
else
	CONFIGURE_ARGS += \
	--with-lzo-include="$(STAGING_DIR)/usr/include/lzo"
endif

ifneq ($(CONFIG_TINC_READLINE),y)
	CONFIGURE_ARGS += \
	--disable-readline
else
	CONFIGURE_ARGS += \
	--with-readline="$(STAGING_DIR)/usr"
endif

ifneq ($(CONFIG_TINC_CURSES),y)
	CONFIGURE_ARGS += \
	--disable-curses
else
	CONFIGURE_ARGS += \
	--with-curses="$(STAGING_DIR)/usr"
endif

ifeq ($(CONFIG_TINC_NOLEGACY),y)
	CONFIGURE_ARGS += \
	--disable-legacy-protocol
endif

define Package/tinc/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/tincd $(1)/usr/sbin/
ifneq ($(CONFIG_TINC_NOCTL),y)
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/tinc ${1}/usr/sbin/
endif
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) files/$(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/etc/tinc
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) files/tinc.upgrade $(1)/lib/upgrade/keep.d/tinc
endef

define Package/tinc/conffiles
/etc/config/tinc
endef

$(eval $(call BuildPackage,tinc))
