cmake_minimum_required(VERSION 3.16)
project(HYBRID_SIDH_SHAKE_MQTT C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

option(USE_PQSIDH "Link with PQCrypto-SIDH" ON)
option(USE_PQSIDH_COMPRESSED "Use compressed P434 API" OFF)

set(SIDH_ROOT "$ENV{HOME}/PQCrypto-SIDH" CACHE PATH "Path to PQCrypto-SIDH root")

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

if(PkgConfig_FOUND)
    pkg_check_modules(MOSQ QUIET libmosquitto)
endif()

if(MOSQ_FOUND)
    message(STATUS "Found libmosquitto via pkg-config")
    add_library(mosquitto_interface INTERFACE)
    target_include_directories(mosquitto_interface INTERFACE ${MOSQ_INCLUDE_DIRS})
    target_link_libraries(mosquitto_interface INTERFACE ${MOSQ_LIBRARIES})
else()
    message(STATUS "pkg-config did not find libmosquitto; using find_library")
    find_library(MOSQUITTO_LIB mosquitto REQUIRED)
    add_library(mosquitto_interface INTERFACE)
    target_link_libraries(mosquitto_interface INTERFACE ${MOSQUITTO_LIB})
endif()

include_directories(${CMAKE_SOURCE_DIR}/src)

if(USE_PQSIDH)
    if(USE_PQSIDH_COMPRESSED)
        set(SIDH_LIB "${SIDH_ROOT}/lib434_compressed/libsidh.a")
    else()
        set(SIDH_LIB "${SIDH_ROOT}/lib434/libsidh.a")
    endif()

    if(NOT EXISTS "${SIDH_LIB}")
        message(FATAL_ERROR
            "libsidh.a not found: ${SIDH_LIB}\n"
            "Build it first, for example:\n"
            "  cd ${SIDH_ROOT}\n"
            "  make clean\n"
            "  make lib434 ARCH=ARM64 CC=gcc OPT_LEVEL=GENERIC"
        )
    endif()
endif()

set(COMMON_SRCS
    src/masking.c
    src/transport.c
)

if(EXISTS "${CMAKE_SOURCE_DIR}/src/sidh_bridge.c")
    list(APPEND COMMON_SRCS src/sidh_bridge.c)
endif()

function(configure_target target_name)
    target_link_libraries(${target_name}
        PRIVATE
            mosquitto_interface
            Threads::Threads
    )

    target_compile_features(${target_name} PRIVATE c_std_11)

    target_include_directories(${target_name}
        PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${SIDH_ROOT}/src
            ${SIDH_ROOT}/src/P434
            ${SIDH_ROOT}/src/sha3
    )

    if(USE_PQSIDH)
        target_include_directories(${target_name}
            PRIVATE
                ${SIDH_ROOT}/src
                ${SIDH_ROOT}/src/P434
        )

        if(USE_PQSIDH_COMPRESSED)
            target_compile_definitions(${target_name} PRIVATE SIDH_BRIDGE_USE_COMPRESSED=1)
        endif()

        target_link_libraries(${target_name} PRIVATE "${SIDH_LIB}")
    endif()
endfunction()

add_executable(alice_mqtt
    src/alice_mqtt.c
    ${COMMON_SRCS}
)
configure_target(alice_mqtt)

add_executable(bob_mqtt
    src/bob_mqtt.c
    ${COMMON_SRCS}
)
configure_target(bob_mqtt)