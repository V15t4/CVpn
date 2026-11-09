cmake_minimum_required(VERSION 3.16)

project(CVpn VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(VPN_SANITIZE "Build with AddressSanitizer and UBSan" OFF)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

if(VPN_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

set(VPN_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wformat=2)

add_library(vpn_core STATIC
  src/constants.cpp
  src/crypto.cpp
  src/network.cpp
  src/routes.cpp
  src/protocol.cpp
  src/tun.cpp
  src/session.cpp
  src/server.cpp
  src/client.cpp
)

target_include_directories(vpn_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(vpn_core PUBLIC OpenSSL::Crypto Threads::Threads)
target_compile_options(vpn_core PRIVATE ${VPN_WARNINGS})

add_executable(CVpn src/main.cpp)
target_link_libraries(CVpn PRIVATE vpn_core)
target_compile_options(CVpn PRIVATE ${VPN_WARNINGS})

include(CTest)
if(BUILD_TESTING)
  add_executable(vpn_tests tests/tests.cpp)
  target_link_libraries(vpn_tests PRIVATE vpn_core)
  target_compile_options(vpn_tests PRIVATE ${VPN_WARNINGS})
  add_test(NAME vpn_tests COMMAND vpn_tests)
endif()

install(TARGETS CVpn RUNTIME DESTINATION bin)
