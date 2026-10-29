cmake_minimum_required(VERSION 3.16)
project(oosockets VERSION 0.1.0 LANGUAGES CXX)

# Builds the native library of sockets.cls against an installed ooRexx:
#   cmake -S . -B build -DOOREXX_HOME=/path/to/oorexx
# OOREXX_HOME holds include/oorexxapi.h and lib/ (the portable builds of
# ooRexx, and the .deb, which installs under /usr/local).

set(OOREXX_HOME "/usr/local" CACHE PATH "Where ooRexx is installed (has include/ and lib/)")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_path(OOREXX_INCLUDE_DIR oorexxapi.h
          PATHS "${OOREXX_HOME}/include" NO_DEFAULT_PATH)
find_library(OOREXX_REXX_LIB NAMES rexx
             PATHS "${OOREXX_HOME}/lib" NO_DEFAULT_PATH)
find_library(OOREXX_REXXAPI_LIB NAMES rexxapi
             PATHS "${OOREXX_HOME}/lib" NO_DEFAULT_PATH)
if(NOT OOREXX_INCLUDE_DIR OR NOT OOREXX_REXX_LIB OR NOT OOREXX_REXXAPI_LIB)
  message(FATAL_ERROR "ooRexx not found under OOREXX_HOME=${OOREXX_HOME} "
                      "(include/oorexxapi.h, lib/rexx, lib/rexxapi)")
endif()

add_library(oosockets SHARED src/oosockets.cpp)
target_compile_definitions(oosockets PRIVATE OOSOCKETS_VERSION="${PROJECT_VERSION}")
target_include_directories(oosockets SYSTEM PRIVATE "${OOREXX_INCLUDE_DIR}")
target_link_libraries(oosockets PRIVATE "${OOREXX_REXX_LIB}" "${OOREXX_REXXAPI_LIB}")

# OpenSSL does the TLS. Linux: the system's (libssl-dev). Windows: vcpkg's
# x64-windows-static-md, through its toolchain file (to be replaced by
# Schannel). macOS: the OpenSSL 3 of Homebrew or MacPorts, which the
# package manager keeps current (Rony, 29/10/2026): ooSockets ships none.
# It is linked weakly, as @rpath/libssl.3.dylib and @rpath/libcrypto.3.dylib,
# with Homebrew's and MacPorts' directories as the rpaths: without it the
# library still loads (the plain sockets work), and TLS says what to
# install (opensslHere in oosockets.cpp). DYLD_LIBRARY_PATH can point
# elsewhere. Point OPENSSL_ROOT_DIR at any OpenSSL 3 to build against
# (Homebrew's openssl@3; the release uses OpenSSL 3.0, the oldest 3.x, so
# that every 3.x has what it calls: probes/macos-openssl/).
if(WIN32)
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL 3.0 REQUIRED)
if(APPLE)
  target_include_directories(oosockets SYSTEM PRIVATE "${OPENSSL_INCLUDE_DIR}")
  set(OOSOCKETS_OPENSSL_RPATHS
      /opt/homebrew/opt/openssl@3/lib            # Homebrew, Apple Silicon
      /usr/local/opt/openssl@3/lib               # Homebrew, Intel (and Rosetta)
      /opt/local/lib/openssl-3                   # MacPorts' openssl3
      /opt/local/libexec/openssl3/lib)
  foreach(lib IN ITEMS "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    target_link_options(oosockets PRIVATE "LINKER:-weak_library,${lib}")
  endforeach()
  foreach(dir IN LISTS OOSOCKETS_OPENSSL_RPATHS)
    target_link_options(oosockets PRIVATE "LINKER:-rpath,${dir}")
  endforeach()
  # The libraries built against name themselves by where they are
  # (Homebrew: /opt/homebrew/opt/openssl@3/lib/libssl.3.dylib); the
  # library must look for them by @rpath.
  foreach(lib IN ITEMS ssl crypto)
    if(lib STREQUAL "ssl")
      set(file "${OPENSSL_SSL_LIBRARY}")
    else()
      set(file "${OPENSSL_CRYPTO_LIBRARY}")
    endif()
    execute_process(COMMAND otool -D "${file}" OUTPUT_VARIABLE out OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX REPLACE ".*\n" "" name "${out}")
    add_custom_command(TARGET oosockets POST_BUILD
      COMMAND install_name_tool -change "${name}" "@rpath/lib${lib}.3.dylib" "$<TARGET_FILE:oosockets>"
      COMMENT "lib${lib}: @rpath/lib${lib}.3.dylib")
  endforeach()
  # install_name_tool spoils the linker's ad hoc signature (arm64 needs one)
  add_custom_command(TARGET oosockets POST_BUILD
    COMMAND codesign --force --sign - "$<TARGET_FILE:oosockets>"
    COMMENT "signed again, ad hoc")
else()
  target_link_libraries(oosockets PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(APPLE)
  # macOS decides trust (SecTrustEvaluateWithError)
  target_link_libraries(oosockets PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

if(WIN32)
  # Windows decides trust (CertGetCertificateChain); OpenSSL's own needs
  target_link_libraries(oosockets PRIVATE ws2_32 iphlpapi crypt32 user32 advapi32)
  target_compile_definitions(oosockets PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

if(MSVC)
  target_compile_options(oosockets PRIVATE /W4)
else()
  target_compile_options(oosockets PRIVATE -Wall -Wextra)
endif()

# sockets.cls next to the library, so that one directory is all a program
# needs (on REXX_PATH, and on the library path).
add_custom_target(sockets_cls ALL
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_SOURCE_DIR}/src/sockets.cls" "$<TARGET_FILE_DIR:oosockets>/sockets.cls"
  DEPENDS oosockets "${CMAKE_SOURCE_DIR}/src/sockets.cls"
  COMMENT "sockets.cls next to the library")

install(TARGETS oosockets LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
install(FILES src/sockets.cls DESTINATION bin)
