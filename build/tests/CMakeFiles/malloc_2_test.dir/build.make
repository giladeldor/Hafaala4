# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/giladeldor/Hafaala4

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/giladeldor/Hafaala4/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/malloc_2_test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/CMakeFiles/malloc_2_test.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/malloc_2_test.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/malloc_2_test.dir/flags.make

tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o: tests/CMakeFiles/malloc_2_test.dir/flags.make
tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o: /home/giladeldor/Hafaala4/tests/malloc_2_test.cpp
tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o: tests/CMakeFiles/malloc_2_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/giladeldor/Hafaala4/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o"
	cd /home/giladeldor/Hafaala4/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o -MF CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o.d -o CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o -c /home/giladeldor/Hafaala4/tests/malloc_2_test.cpp

tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.i"
	cd /home/giladeldor/Hafaala4/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/giladeldor/Hafaala4/tests/malloc_2_test.cpp > CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.i

tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.s"
	cd /home/giladeldor/Hafaala4/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/giladeldor/Hafaala4/tests/malloc_2_test.cpp -o CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.s

tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o: tests/CMakeFiles/malloc_2_test.dir/flags.make
tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o: /home/giladeldor/Hafaala4/malloc_2.cpp
tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o: tests/CMakeFiles/malloc_2_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/giladeldor/Hafaala4/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o"
	cd /home/giladeldor/Hafaala4/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o -MF CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o.d -o CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o -c /home/giladeldor/Hafaala4/malloc_2.cpp

tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.i"
	cd /home/giladeldor/Hafaala4/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/giladeldor/Hafaala4/malloc_2.cpp > CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.i

tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.s"
	cd /home/giladeldor/Hafaala4/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/giladeldor/Hafaala4/malloc_2.cpp -o CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.s

# Object files for target malloc_2_test
malloc_2_test_OBJECTS = \
"CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o" \
"CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o"

# External object files for target malloc_2_test
malloc_2_test_EXTERNAL_OBJECTS =

tests/malloc_2_test: tests/CMakeFiles/malloc_2_test.dir/malloc_2_test.cpp.o
tests/malloc_2_test: tests/CMakeFiles/malloc_2_test.dir/__/malloc_2.cpp.o
tests/malloc_2_test: tests/CMakeFiles/malloc_2_test.dir/build.make
tests/malloc_2_test: _deps/catch2-build/src/libCatch2Main.a
tests/malloc_2_test: _deps/catch2-build/src/libCatch2.a
tests/malloc_2_test: tests/CMakeFiles/malloc_2_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/giladeldor/Hafaala4/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable malloc_2_test"
	cd /home/giladeldor/Hafaala4/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/malloc_2_test.dir/link.txt --verbose=$(VERBOSE)
	cd /home/giladeldor/Hafaala4/build/tests && /usr/bin/cmake -D TEST_TARGET=malloc_2_test -D TEST_EXECUTABLE=/home/giladeldor/Hafaala4/build/tests/malloc_2_test -D TEST_EXECUTOR= -D TEST_WORKING_DIR=/home/giladeldor/Hafaala4/build/tests -D TEST_SPEC= -D TEST_EXTRA_ARGS= -D TEST_PROPERTIES= -D TEST_PREFIX=malloc_2. -D TEST_SUFFIX= -D TEST_LIST=malloc_2_test_TESTS -D TEST_REPORTER= -D TEST_OUTPUT_DIR= -D TEST_OUTPUT_PREFIX= -D TEST_OUTPUT_SUFFIX= -D CTEST_FILE=/home/giladeldor/Hafaala4/build/tests/malloc_2_test_tests-b12d07c.cmake -P /home/giladeldor/Hafaala4/build/_deps/catch2-src/extras/CatchAddTests.cmake

# Rule to build all files generated by this target.
tests/CMakeFiles/malloc_2_test.dir/build: tests/malloc_2_test
.PHONY : tests/CMakeFiles/malloc_2_test.dir/build

tests/CMakeFiles/malloc_2_test.dir/clean:
	cd /home/giladeldor/Hafaala4/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/malloc_2_test.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/malloc_2_test.dir/clean

tests/CMakeFiles/malloc_2_test.dir/depend:
	cd /home/giladeldor/Hafaala4/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/giladeldor/Hafaala4 /home/giladeldor/Hafaala4/tests /home/giladeldor/Hafaala4/build /home/giladeldor/Hafaala4/build/tests /home/giladeldor/Hafaala4/build/tests/CMakeFiles/malloc_2_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/malloc_2_test.dir/depend
