# The Schannel probe: Windows' own TLS, nothing else.
cmake_minimum_required(VERSION 3.15)
project(schannel_probe C)
add_executable(probe probe.c)
target_link_libraries(probe ws2_32 secur32 crypt32 ncrypt)
# What Windows does with a PKCS#12 file's private keys (keys.c).
add_executable(keys keys.c)
target_link_libraries(keys secur32 crypt32 ncrypt)
