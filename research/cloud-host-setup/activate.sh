# Source this file in each command shell used for OpenWrt host development.
export OPENWRT_HOST_PREFIX=/workspace/.openwrt-onboarding/host
export PATH="/workspace/.openwrt-onboarding/bin:$OPENWRT_HOST_PREFIX/usr/bin:$PATH"
export LD_LIBRARY_PATH="$OPENWRT_HOST_PREFIX/usr/lib/x86_64-linux-gnu:$OPENWRT_HOST_PREFIX/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# Native compiler wrappers set include/library paths for native gcc and g++
# only. Keep cross-compiler include and library search environments untouched.
export PYTHONPATH="$OPENWRT_HOST_PREFIX/usr/lib/python3/dist-packages${PYTHONPATH:+:$PYTHONPATH}"
export PERL5LIB="$OPENWRT_HOST_PREFIX/usr/share/automake-1.17:$OPENWRT_HOST_PREFIX/usr/share/autoconf${PERL5LIB:+:$PERL5LIB}"
export BISON_PKGDATADIR="$OPENWRT_HOST_PREFIX/usr/share/bison"
export SWIG_LIB="$OPENWRT_HOST_PREFIX/usr/share/swig/4.3.0"
export autom4te_perllibdir="$OPENWRT_HOST_PREFIX/usr/share/autoconf"
export AC_MACRODIR="$OPENWRT_HOST_PREFIX/usr/share/autoconf"
export AUTOM4TE_CFG=/workspace/.openwrt-onboarding/autom4te.cfg
export trailer_m4="$OPENWRT_HOST_PREFIX/usr/share/autoconf/autoconf/trailer.m4"
export M4="$OPENWRT_HOST_PREFIX/usr/bin/m4"
export AUTOCONF="$OPENWRT_HOST_PREFIX/usr/bin/autoconf"
export AUTOHEADER="$OPENWRT_HOST_PREFIX/usr/bin/autoheader"
export AUTOM4TE="$OPENWRT_HOST_PREFIX/usr/bin/autom4te"
export AUTOMAKE="$OPENWRT_HOST_PREFIX/usr/bin/automake"
export AUTOMAKE_LIBDIR="$OPENWRT_HOST_PREFIX/usr/share/automake-1.17"
export ACLOCAL="$OPENWRT_HOST_PREFIX/usr/bin/aclocal"
export ACLOCAL_AUTOMAKE_DIR="$OPENWRT_HOST_PREFIX/usr/share/aclocal-1.17"
export ACLOCAL_PATH="$OPENWRT_HOST_PREFIX/usr/share/aclocal${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
export _lt_pkgdatadir="$OPENWRT_HOST_PREFIX/usr/share/libtool"
export gettext_datadir="$OPENWRT_HOST_PREFIX/usr/share/gettext"
export CCACHE_DIR=/workspace/.openwrt-onboarding/ccache
OPENWRT_BUILD_JOBS=$(nproc)
if [ "$OPENWRT_BUILD_JOBS" -gt 4 ]; then OPENWRT_BUILD_JOBS=4; fi
export OPENWRT_BUILD_JOBS
umask 022
