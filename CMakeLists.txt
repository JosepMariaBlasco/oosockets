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
target_include_directories(oosockets SYSTEM PRIVATE "${OOREXX_INCLUDE_DIR}")
target_link_libraries(oosockets PRIVATE "${OOREXX_REXX_LIB}" "${OOREXX_REXXAPI_LIB}")

if(WIN32)
  target_link_libraries(oosockets PRIVATE ws2_32)
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
