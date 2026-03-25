cmake_minimum_required(VERSION 3.15)
project(osslCryptoLibrary CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# --- OpenLDAP (libldap + liblber) ---
add_library(OpenLDAP INTERFACE)
if(WIN32)
    find_path(LDAP_INCLUDE_DIR ldap.h REQUIRED)
    find_library(LDAP_LIB ldap REQUIRED)
    find_library(LBER_LIB lber REQUIRED)
    target_include_directories(OpenLDAP INTERFACE "${LDAP_INCLUDE_DIR}")
    target_link_libraries(OpenLDAP INTERFACE "${LDAP_LIB}" "${LBER_LIB}")
else()
    if(NOT LDAP_ROOT)
        set(LDAP_ROOT "/home/linuxbrew/.linuxbrew/Cellar/openldap/2.6.13")
    endif()
    find_library(LDAP_LIB ldap HINTS "${LDAP_ROOT}/lib" REQUIRED)
    find_library(LBER_LIB lber HINTS "${LDAP_ROOT}/lib" REQUIRED)
    target_include_directories(OpenLDAP INTERFACE "${LDAP_ROOT}/include")
    target_link_libraries(OpenLDAP INTERFACE "${LDAP_LIB}" "${LBER_LIB}")
endif()

# --- Library ---
add_library(osslCrypto STATIC
    osslCertificate.cpp
    osslLdapClient.cpp
    osslOcspClient.cpp
    osslCryptoPki.cpp
)

target_include_directories(osslCrypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(osslCrypto PUBLIC OpenSSL::SSL OpenSSL::Crypto OpenLDAP)

# --- MSVC compile definitions ---
if(MSVC)
    target_compile_definitions(osslCrypto PUBLIC
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0601
    )
endif()

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
