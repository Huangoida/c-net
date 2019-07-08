cmake_minimum_required(VERSION 3.14)
project(dfasd)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_FLAGS_DEBUG "-g -lpcap -lm")
set(CMAKE_CXX_FLAGS_RELEASE  "-lpcap -lm")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-lpcap")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO  "-lcap")
add_executable(dfasd main.cpp cJSON.cpp)