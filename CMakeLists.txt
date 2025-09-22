cmake_minimum_required(VERSION 3.14)
project(denc LANGUAGES C)

# Set output directory for executable to project root, like in Makefile
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_PROJECT_SOURCE_DIR})

# Include directory for denc project's headers
include_directories(include)

# Build type (Release/Debug)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose Release or Debug" FORCE)
endif()

# Compiler flags based on Makefile and CMakeLists_easystd.txt
if(MSVC)
    # MSVC (cl)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /MP /permissive-")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Zi /Od")
else()
    # GCC/Clang
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
    # Use C23 if supported, otherwise C11 (from Makefile)
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-std=c23" HAS_C23_FLAG)
    if(HAS_C23_FLAG)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c23")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")
    endif()
endif()

# Find easystd library and headers.
# This assumes easystd has been installed to a standard location
# (e.g., /usr/local/lib, /usr/local/include) by the other CMakeLists.txt.
find_library(EASYSTD_LIBRARY NAMES estd HINTS /usr/local/lib)
find_path(EASYSTD_INCLUDE_DIR NAMES estd.h HINTS /usr/local/include)

if(NOT EASYSTD_LIBRARY)
    message(FATAL_ERROR "easystd library not found. Please compile and install it using CMakeLists_easystd.txt first.")
endif()

if(NOT EASYSTD_INCLUDE_DIR)
    message(FATAL_ERROR "easystd headers not found. Please install them first.")
endif()

# Add easystd include directory
include_directories(${EASYSTD_INCLUDE_DIR})

# Source files for denc
file(GLOB DENC_SRC "src/*.c")

# Add executable
add_executable(denc ${DENC_SRC})

# Link libraries
target_link_libraries(denc PRIVATE ${EASYSTD_LIBRARY})

# Platform-specific link libraries (from CMakeLists_easystd.txt)
if(NOT MSVC)
    target_link_libraries(denc PRIVATE m)
endif()
