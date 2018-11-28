cmake_minimum_required(VERSION 2.8)

project(ALISIGN)

# silence policy CMP0042 warning by enabling RPATH explicitly
if(APPLE AND NOT DEFINED CMAKE_MACOSX_RPATH)
  set(CMAKE_MACOSX_RPATH TRUE)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(BUILD_SHARED_LIBS ON)

if (NOT LUAJIT_ROOT_DIR)
  set(LUAJIT_ROOT_DIR "${CMAKE_INSTALL_PREFIX}/openresty/luajit")
endif()
message("LUAJIT_ROOT_DIR = " ${LUAJIT_ROOT_DIR})

find_package(OpenSSL REQUIRED)

include_directories(
  ${OPENSSL_INCLUDE_DIR}
  ${LUAJIT_ROOT_DIR}/include/luajit-2.1
)
link_directories(${LUAJIT_ROOT_DIR}/lib)

add_subdirectory(src)
