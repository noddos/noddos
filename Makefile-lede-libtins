##############################################
# OpenWrt Makefile for Noddos (https://github.com/noddos/noddos/)
#
#
# Most of the variables used here are defined in
# the include directives below. We just need to
# specify a basic description of the package,
# where to build our program, where to find
# the source files, and where to install the
# compiled program on the router.
#
# Be very careful of spacing in this file.
# Indents should be tabs, not spaces, and
# there should be no trailing whitespace in
# lines that are not commented.
#
##############################################

include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=libtins
PKG_RELEASE:=1
PKG_LICENSE:=BSD-2
CMAKE_INSTALL:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/mfontanini/libtins.git
#PKG_VERSION:=37c92fc
PKG_SOURCE_VERSION:=37c92fc
PKG_SOURCE_SUBDIR:=$(PKG_NAME)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.gz

# This specifies the directory where we're going to build the program.
# The root build directory, $(BUILD_DIR), is by default the build_mipsel
# directory in your OpenWrt SDK directory
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk


# Specify package information for this program.
# The variables defined here should be self explanatory.
define Package/libtins
	SECTION:=net
	CATEGORY:=Libraries
	TITLE:=libtins 
	URL:=http://libtins.github.io/
	DEPENDS:=+libstdcpp +libpcap +libopenssl
endef

define Package/libtins/description
libtins is a high-level, multiplatform C++ network packet sniffing and crafting library.
endef

# Specify what needs to be done to prepare for building the package.
# In our case, we need to copy the source files to the build directory.
# This is NOT the default. The default uses the PKG_SOURCE_URL and the
# PKG_SOURCE which is not defined here to download the source from the web.
# In order to just build a simple program that we have just written, it is
# much easier to do it this way.
#define Build/Prepare
#	mkdir -p $(PKG_BUILD_DIR)
#	$(CP) ./src/* $(PKG_BUILD_DIR)/
#endef

# We do not need to define Build/Configure or Build/Compile directives
# The defaults are appropriate for compiling a simple program such as this one

#define Build/Compile
#    $(MAKE) libtins
#endef

# Specify where and how to install the program. Since we only have one file,
# the noddos executable, install it by copying it to the /bin directory on
# the router. The $(1) variable represents the root directory on the router running
# OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install
# directory if it does not already exist. Likewise $(INSTALL_BIN) contains the
# command to copy the binary file from its current location (in our case the build
# directory) to the install directory.
define Package/libtins/install
    $(INSTALL_DIR) $(1)/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/lib/libtins.so.3.5 $(1)/lib/
endef


# This line executes the necessary commands to compile our program.
# The above define directives specify all the information needed, but this
# line calls BuildPackage which in turn actually uses this information to
# build a package.
$(eval $(call BuildPackage,libtins))
