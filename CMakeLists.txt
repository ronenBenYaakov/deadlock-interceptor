cmake_minimum_required(VERSION 3.10)
project(DeadlockInspector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON) # Needed for shared library

# ----------------------------
# Build the inspector library
# ----------------------------
add_library(inspector SHARED app.cpp)

# Link required libraries
target_link_libraries(inspector dl pthread)

# Set output name to libinspector.so
set_target_properties(inspector PROPERTIES OUTPUT_NAME "inspector")

# ----------------------------
# (Optional) Build test program
# ----------------------------
add_executable(test_main main.cpp)
target_link_libraries(test_main pthread)
