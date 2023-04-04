cmake_minimum_required(VERSION 3.16)

project(EncryptionDecryption)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_subdirectory(openssl)
add_subdirectory(base64)

add_executable(Crypto main.cpp)

target_link_libraries(Crypto PUBLIC openssl base64)