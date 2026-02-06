cmake_minimum_required(VERSION 3.16)
project(deadlock-interceptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Executable
add_executable(deadlock-interceptor
    src/main.cpp
    src/detection.cpp
    src/helpers.cpp
    src/memory_duplication.cpp
    src/monitoring.cpp
    src/snapshot.cpp
    src/strategy1.cpp
)

# Public headers
target_include_directories(deadlock-interceptor 
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Warnings (nice to have)
target_compile_options(deadlock-interceptor 
    PRIVATE
        -Wall -Wextra -Wpedantic
)
