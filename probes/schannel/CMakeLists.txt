# The Schannel probe: Windows' own TLS, nothing else.
cmake_minimum_required(VERSION 3.15)
project(schannel_probe C)
add_executable(probe probe.c)
target_link_libraries(probe ws2_32 secur32 crypt32 ncrypt)
