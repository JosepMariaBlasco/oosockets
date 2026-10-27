# The multicast probe (probe.c), on the three systems.
cmake_minimum_required(VERSION 3.15)
project(multicast_probe C)
add_executable(probe probe.c)
if(WIN32)
  target_link_libraries(probe ws2_32 iphlpapi)
endif()
