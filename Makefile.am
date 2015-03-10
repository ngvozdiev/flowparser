AM_CPPFLAGS = -g -pthread -std=c++11 -pedantic-errors -Werror -Winit-self -Wold-style-cast -Woverloaded-virtual -Wuninitialized -Wall -Wextra -O2

lib_LTLIBRARIES = libflowparser.la
libflowparser_la_SOURCES = common.cc common.h flows.cc flows.h packer.cc packer.h parser.cc parser.h flowparser.cc ptr_queue.h

libflowparser_la_LDFLAGS = -version-info 0:2:0
include_HEADERS = flowparser.h

# Unit tests
noinst_LIBRARIES = libgtest.a
libgtest_a_SOURCES = gtest/src/gtest-all.cc gtest/src/gtest_main.cc
libgtest_a_CPPFLAGS = -isystem gtest/include -Igtest -pthread

noinst_PROGRAMS = packer_test flows_test ptr_queue_test parser_test

packer_test_SOURCES = $(libflowparser_la_SOURCES) common_test.h packer_test.cc
packer_test_CPPFLAGS = $(AM_CPPFLAGS) -isystem gtest/include -Igtest
packer_test_LDADD = libflowparser.la libgtest.a

flows_test_SOURCES = $(libflowparser_la_SOURCES) common_test.h flows_test.cc
flows_test_CPPFLAGS = $(AM_CPPFLAGS) -isystem gtest/include -Igtest
flows_test_LDADD = libflowparser.la libgtest.a

ptr_queue_test_SOURCES = $(libflowparser_la_SOURCES) common_test.h ptr_queue_test.cc
ptr_queue_test_CPPFLAGS = $(AM_CPPFLAGS) -isystem gtest/include -Igtest
ptr_queue_test_LDADD = libflowparser.la libgtest.a

parser_test_SOURCES = $(libflowparser_la_SOURCES) common_test.h parser_test.cc
parser_test_CPPFLAGS = $(AM_CPPFLAGS) -isystem gtest/include -Igtest
parser_test_LDADD = libflowparser.la libgtest.a

TESTS = packer_test flows_test ptr_queue_test parser_test

