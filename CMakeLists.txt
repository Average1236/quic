cmake_minimum_required(VERSION 3.10)
project(xquic_wifi_comm)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. 定位XQUIC静态库和头文件
set(XQUIC_ROOT ${CMAKE_SOURCE_DIR}/third_party/xquic/build)  # 指向XQUIC的构建目录
find_library(XQC_STATIC_LIB libxquic-static.a HINTS ${XQUIC_ROOT} REQUIRED)
if(XQC_STATIC_LIB)
    message(STATUS "Found XQUIC static library: ${XQC_STATIC_LIB}")
else()
    message(FATAL_ERROR "XQUIC static library not found")
endif()
# find_path(XQC_INCLUDE_DIR xqc.h HINTS ${XQUIC_ROOT}/include REQUIRED)

# 2. 定位依赖的SSL库（以BabaSSL为例）
set(SSL_TYPE "babassl")
set(SSL_PATH ${CMAKE_SOURCE_DIR}/third_party/xquic/third_party/babassl/build)
find_library(SSL_LIB libssl.a HINTS ${SSL_PATH}/lib REQUIRED)
find_library(CRYPTO_LIB libcrypto.a HINTS ${SSL_PATH}/lib REQUIRED)
if(SSL_LIB)
    message(STATUS "Found SSL library: ${SSL_LIB}")
else()
    message(FATAL_ERROR "SSL library not found")
endif()
if(CRYPTO_LIB)
    message(STATUS "Found Crypto library: ${CRYPTO_LIB}")
else()
    message(FATAL_ERROR "Crypto library not found")
endif()


aux_source_directory(${CMAKE_SOURCE_DIR}/src SRC_FILES)
# aux_source_directory(${CMAKE_SOURCE_DIR}/third_party/xquic/mini SRC_FILES)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/xquic)
include_directories(${CMAKE_SOURCE_DIR}/include/src/common)
include_directories(${CMAKE_SOURCE_DIR}/include/src/transport)
include_directories(${CMAKE_SOURCE_DIR}/include/src/tls)
include_directories(${CMAKE_SOURCE_DIR}/include/src/http3)
include_directories(${CMAKE_SOURCE_DIR}/include/src/congestion_control)

# add_subdirectory(third_party/xquic)

# 添加可执行文件
add_executable(xquic_target ${SRC_FILES})

target_include_directories(xquic_target PRIVATE ${CMAKE_SOURCE_DIR}/include ${SSL_PATH}/include)

# 链接XQUIC库
target_link_libraries(xquic_target PRIVATE ${XQC_STATIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} gcov event)

target_compile_options(xquic_target PRIVATE
    -DUSE_XQUIC=1  # 如果需要定义宏
)

add_definitions(-D_POSIX_C_SOURCE=200112L)