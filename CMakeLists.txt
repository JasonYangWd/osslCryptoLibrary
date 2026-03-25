cmake_minimum_required(VERSION 3.15)
project(osslCryptoLibrary CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# --- OpenLDAP (libldap + liblber) ---
set(LDAP_ROOT "/home/linuxbrew/.linuxbrew/Cellar/openldap/2.6.13")
find_library(LDAP_LIB  ldap  HINTS "${LDAP_ROOT}/lib" REQUIRED)
find_library(LBER_LIB  lber  HINTS "${LDAP_ROOT}/lib" REQUIRED)
add_library(OpenLDAP INTERFACE)
target_include_directories(OpenLDAP INTERFACE "${LDAP_ROOT}/include")
target_link_libraries(OpenLDAP INTERFACE "${LDAP_LIB}" "${LBER_LIB}")

# --- Library ---
add_library(osslCrypto STATIC
    osslCertificate.cpp
    osslLdapClient.cpp
    osslOcspClient.cpp
    osslCryptoPki.cpp
)

target_include_directories(osslCrypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(osslCrypto PUBLIC OpenSSL::SSL OpenSSL::Crypto OpenLDAP)

# --- Demo executable ---
add_executable(demo demo.cpp)
target_link_libraries(demo PRIVATE osslCrypto)

# --- Certificate loader ---
add_executable(load_certs load_certs.cpp)
target_link_libraries(load_certs PRIVATE osslCrypto)

# --- LDAP demo ---
add_executable(ldap_demo ldap_demo.cpp)
target_link_libraries(ldap_demo PRIVATE osslCrypto)

# --- OCSP client + demo ---
add_executable(ocsp_demo ocsp_demo.cpp)
target_link_libraries(ocsp_demo PRIVATE osslCrypto)

# --- PKI crypto demo ---
add_executable(crypto_demo crypto_demo.cpp)
target_link_libraries(crypto_demo PRIVATE osslCrypto)
