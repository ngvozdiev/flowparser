CXX=g++
CXXFLAGS=-g -pthread -std=c++11 -pedantic-errors -Werror -Winit-self -Wold-style-cast -Woverloaded-virtual -Wuninitialized -Wall -Wextra -O0
GTEST_DIR = gtest
GTEST_FLAGS=-isystem $(GTEST_DIR)/include
LDFLAGS=-g -lpcap -pthread
LDLIBS=
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h
GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

SRCS=flows.cc packer.cc common.cc parser.cc flowparser.cc
OBJS=$(subst .cc,.o,$(SRCS))
RM=rm -f

gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(GTEST_FLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -Wno-missing-field-initializers -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(GTEST_FLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -Wno-missing-field-initializers -c \
            $(GTEST_DIR)/src/gtest_main.cc

common.o: common.cc common.h

packer.o: packer.cc packer.h common.o

flows.o: flows.cc flows.h common.o packer.o

parser.o: parser.cc parser.h flows.o

flowparser.o: flowparser.cc flowparser.h parser.o

# Tests
flows_test.o: flows_test.cc common_test.h flows.o
	$(CXX) $(GTEST_FLAGS) $(CXXFLAGS) -c flows_test.cc

flows_test: flows_test.o gtest_main.o gtest-all.o $(OBJS)
	$(CXX) $(GTEST_FLAGS) $^ -o $@ $(LDFLAGS)

packer_test.o: packer_test.cc packer.o
	$(CXX) $(GTEST_FLAGS) $(CXXFLAGS) -c packer_test.cc

packer_test: packer_test.o gtest_main.o gtest-all.o $(OBJS)
	$(CXX) $(GTEST_FLAGS) $^ -o $@ $(LDFLAGS)

parser_test.o: parser_test.cc common_test.h parser.o
	$(CXX) $(GTEST_FLAGS) $(CXXFLAGS) -c parser_test.cc

parser_test: parser_test.o gtest_main.o gtest-all.o $(OBJS)
	$(CXX) $(GTEST_FLAGS) $^ -o $@ $(LDFLAGS)

flowparser_test.o: flowparser_test.cc flowparser.o
	$(CXX) $(GTEST_FLAGS) $(CXXFLAGS) -c flowparser_test.cc

flowparser_test: flowparser_test.o gtest_main.o gtest-all.o $(OBJS)
	$(CXX) $(GTEST_FLAGS) $^ -o $@ $(LDFLAGS)

# Examples

examples/binner.pb.o: examples/binner.pb.cc

examples/binner.pb.cc: examples/binner.proto
	protoc --cpp_out=examples --python_out=examples --proto_path=examples examples/binner.proto

examples/binner.o: examples/binner.cc examples/binner.pb.o flowparser.o

examples/binner: examples/binner.o examples/binner.pb.o $(OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS) -lprotobuf

clean:
	$(RM) *.o *.a *.gcov *.gcda *.gcno *_test 

