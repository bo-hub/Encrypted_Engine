cmake_minimum_required(VERSION 3.17)
project(evp_file_encrypted_engine)

set(CMAKE_CXX_STANDARD 14)
link_libraries(crypto)
add_executable(evpfile evp_file_encryption/main.cpp evp_file_encryption/evp_file.cpp evp_file_encryption/evp_file.h)
add_executable(evpdigest evp_digest/evp_test_digest.cpp)
add_executable(strEnc string_encryption/string_encryption.cpp)
add_executable(evpfile1 evp_file_encryption1/evp_test_cipher_file.cpp)
