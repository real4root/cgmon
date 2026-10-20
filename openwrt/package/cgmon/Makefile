# SPDX-License-Identifier: GPL-3.0-or-later
#
# cgmon — uplink, port and device monitor for OpenWrt that only loads kernel
# rules (nftables, ip rules/routes, tc, DNS); no traffic passes through it.

include $(TOPDIR)/rules.mk

PKG_NAME:=cgmon
PKG_VERSION:=2.4.22
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/real4root/cgmon/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=d04672e514ef5a85eab130f598fcdab81e00cdac19d71f8dfba96816239c7d2f

PKG_MAINTAINER:=real4root <real4root@gmail.com>
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include ../../lang/rust/rust-package.mk

define Package/cgmon/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Network monitoring
  TITLE:=Uplink, port and device monitor
  URL:=https://github.com/real4root/cgmon
  DEPENDS:=$(RUST_ARCH_DEPENDS) +nftables
endef

define Package/cgmon
  $(call Package/cgmon/Default)
  TITLE+= (full)
  VARIANT:=full
  DEFAULT_VARIANT:=1
endef

define Package/cgmon-lite
  $(call Package/cgmon/Default)
  TITLE+= (lite, without SmartDNS features)
  VARIANT:=lite
  CONFLICTS:=cgmon
endef

define Package/cgmon-nano
  $(call Package/cgmon/Default)
  TITLE+= (nano, stock image only)
  VARIANT:=nano
  CONFLICTS:=cgmon cgmon-lite
endef

define Package/cgmon/description/Default
  cgmon watches the internet uplink (IPv4 and IPv6, CGNAT-aware), sites your
  clients cannot reach, switch ports and cables (link drops, CRC errors),
  devices and traffic, and shows it all on a web page with Telegram alerts
  and a hub for several routers. It never forwards traffic itself: the kernel
  does; cgmon only loads its own nftables tables, ip rules/routes and tc
  queues when a feature is enabled. Observe-only by default.
endef

define Package/cgmon/description
  $(call Package/cgmon/description/Default)
  This build has every feature, including the SmartDNS-based targeted
  DNS guard and rerouting.
endef

define Package/cgmon-lite/description
  $(call Package/cgmon/description/Default)
  This build has everything except the SmartDNS-based features.
endef

define Package/cgmon-nano/description
  $(call Package/cgmon/description/Default)
  This build targets small routers and needs only what a stock image
  provides; SQM is available once tc and sch_cake are installed.
endef

define Package/cgmon/conffiles
/etc/cgmon/cgmon.yaml
endef
Package/cgmon-lite/conffiles=$(Package/cgmon/conffiles)
Package/cgmon-nano/conffiles=$(Package/cgmon/conffiles)

# .cargo/config.toml in the tree sets the developer's own linkers (zig, rust-lld);
# the OpenWrt toolchain provides its own.
define Build/Prepare
	$(call Build/Prepare/Default)
	rm -f $(PKG_BUILD_DIR)/.cargo/config.toml
endef

define Build/Compile
	$(call Build/Compile/Cargo,,--no-default-features --features $(BUILD_VARIANT))
endef

define Package/cgmon/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/cgmon
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/cgmon $(1)/usr/sbin/cgmon
	$(INSTALL_BIN) ./files/cgmon.init $(1)/etc/init.d/cgmon
	$(INSTALL_CONF) ./files/cgmon.yaml $(1)/etc/cgmon/cgmon.yaml
endef
Package/cgmon-lite/install=$(Package/cgmon/install)
Package/cgmon-nano/install=$(Package/cgmon/install)

$(eval $(call BuildPackage,cgmon))
$(eval $(call BuildPackage,cgmon-lite))
$(eval $(call BuildPackage,cgmon-nano))
