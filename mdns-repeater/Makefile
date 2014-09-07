include $(TOPDIR)/rules.mk

PKG_NAME:=mdns-repeater
PKG_VERSION:=1.1402
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://dl.scu.red/projects/mdns-repeater

include $(INCLUDE_DIR)/package.mk

define Package/mdns-repeater
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Multicast DNS Repeater
  URL:=https://dl.scu.red/projects/mdns-repeater
endef

define Package/mdns-repeater/description
 Re-broadcasts mDNS packets from one interface to other interfaces,
 in order to overcome the "administratively scoped" limitations of
 Multicast DNS
endef

define Package/mdns-repeater/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mdns-repeater $(1)/usr/sbin
endef

$(eval $(call BuildPackage,mdns-repeater))
