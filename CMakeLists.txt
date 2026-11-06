cmake_minimum_required(VERSION 3.16)
project(scramjet_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Boost 1.74 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
find_package(PostgreSQL REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(scramjet_server
  src/main.cpp
  src/config.cpp
  src/db.cpp
  src/auth.cpp
  src/static_files.cpp
  src/http_server.cpp
  src/wisp_session.cpp
  src/net_policy.cpp
)
target_include_directories(scramjet_server PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(scramjet_server PRIVATE
  ZLIB::ZLIB Threads::Threads PostgreSQL::PostgreSQL OpenSSL::Crypto)
target_compile_options(scramjet_server PRIVATE -Wall -Wextra -O2)
