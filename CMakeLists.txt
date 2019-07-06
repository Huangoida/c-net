cmake_minimum_required(VERSION 3.14)
project(dfasd)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_FLAGS_DEBUG "-g -lpcap")
set(CMAKE_CXX_FLAGS_RELEASE  "-lpcap")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-lpcap")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO  "-lcap")
add_executable(dfasd main.cpp)