cmake_minimum_required(VERSION 3.16)

project(network_processor
    VERSION 0.1.0
    DESCRIPTION "Network packet processor"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_library(np_warnings INTERFACE)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(np_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow)
elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(np_warnings INTERFACE /W4)
endif()

add_library(np STATIC src/packet.c)
target_include_directories(np PUBLIC include)
target_link_libraries(np PRIVATE np_warnings)

add_executable(network_processor src/main.c)
target_link_libraries(network_processor PRIVATE np np_warnings)

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
