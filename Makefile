CXX=g++
CXXFLAGS=-g -pthread -std=c++11 -pedantic-errors -Winit-self -Wold-style-cast -Woverloaded-virtual -Wuninitialized -Wextra -O0
GTEST_DIR = gtest
GTEST_FLAGS=-isystem $(GTEST_DIR)/include
LDFLAGS=-g -lpcap -pthread
LDLIBS=
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h
GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

SRCS=flows.cc packer.cc common.cc
OBJS=$(subst .cc,.o,$(SRCS))
RM=rm -f

gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(GTEST_FLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest-all.cc

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(GTEST_FLAGS) -I$(GTEST_DIR) $(CXXFLAGS) -c \
            $(GTEST_DIR)/src/gtest_main.cc

common.o: common.cc common.h

packer.o: packer.cc packer.h common.o

flows.o: flows.cc flows.h common.o

# Tests
flows_test.o: flows_test.cc flows.o
	$(CXX) $(GTEST_FLAGS) $(CXXFLAGS) -c flows_test.cc

flows_test: flows_test.o gtest_main.o gtest-all.o $(OBJS)
	$(CXX) $(GTEST_FLAGS) $^ -o $@ $(LDFLAGS)

packer_test.o: packer_test.cc packer.o
	$(CXX) $(GTEST_FLAGS) $(CXXFLAGS) -c packer_test.cc

packer_test: packer_test.o gtest_main.o gtest-all.o $(OBJS)
	$(CXX) $(GTEST_FLAGS) $^ -o $@ $(LDFLAGS)

clean:
	$(RM) *.o *.a *.gcov *.gcda *.gcno *_test 

