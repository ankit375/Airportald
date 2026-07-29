include $(TOPDIR)/rules.mk

PKG_NAME:=airportal
PKG_VERSION:=0.1.0
PKG_RELEASE:=9

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/airportal
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AirPortal captive access-control daemon
  DEPENDS:=+libev +libubus +libubox +libuci +libopenssl +jansson +nftables-json +tc +kmod-sched-core +kmod-sched-flower +kmod-sched-act-police
  MAINTAINER:=AirPro
endef

define Package/airportal/description
 airportald is a captive access-control daemon for OpenWrt access points.
 It uses normal kernel forwarding with nftables admission control and a
 small local redirect service. Phase 1 supports local/manual authorization.
endef

define Package/airportal/conffiles
/etc/config/airportal
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./include $(PKG_BUILD_DIR)/
	$(CP) ./src $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		AIRPORTAL_OPENWRT=1
endef

define Package/airportal/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/airportald $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/sbin/airportal-coova-import $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/airportal $(1)/etc/config/airportal
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/airportal $(1)/etc/init.d/airportal
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) ./files/etc/hotplug.d/iface/90-airportal $(1)/etc/hotplug.d/iface/90-airportal
	$(INSTALL_DIR) $(1)/etc/airportal/secrets
endef

$(eval $(call BuildPackage,airportal))
