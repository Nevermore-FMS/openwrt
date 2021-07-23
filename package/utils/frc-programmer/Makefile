#
# Copyright (C) 2021 Chase MacDonnell <macdonnell.chase@gmail.com>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=frc-programmer
PKG_RELEASE:=1

PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk

define Package/frc-programmer
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=Utility for running a FRC Radio Programmer compatible TCP server.
  MAINTAINER:=Chase MacDonnell <macdonnell.chase@gmail.com>
endef

define Package/frc-programmer/description
 This package contains an utility for running a FRC Radio Programmer compatible TCP server.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall"
endef

define Package/frc-programmer/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/frc-programmer $(1)/bin/
endef

$(eval $(call BuildPackage,frc-programmer))
