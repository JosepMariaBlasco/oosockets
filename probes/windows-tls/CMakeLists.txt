# The Windows TLS probe, against vcpkg's OpenSSL (x64-windows-static).
cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)
project(windows_tls_probe C)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
add_executable(probe probe.c)
target_link_libraries(probe OpenSSL::SSL OpenSSL::Crypto ws2_32 crypt32 user32 advapi32)
