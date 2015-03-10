#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([flowparser], [0.2], [nikgvozdiev_at_gmail.com])
AC_CONFIG_SRCDIR([common.cc])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [pcap_lookupdev], [], [
	echo "libpcap is required"
	exit -1])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_CONFIG_SUBDIRS([gtest])
AC_OUTPUT
