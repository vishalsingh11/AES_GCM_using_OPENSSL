add_library(openssl src/openssl.cpp)

target_include_directories(openssl PUBLIC include)

target_link_libraries(openssl PUBLIC OpenSSL::Crypto OpenSSL::SSL)