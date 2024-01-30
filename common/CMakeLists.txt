
target_sources(${TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/networking.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/logging.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/poll_set.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/wolfssl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_parsing.c

        # ${CMAKE_CURRENT_SOURCE_DIR}/src/secure_element/secure_element.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/secure_element/wolfssl_pkcs11_pqc.c
)

target_include_directories(${TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        # ${CMAKE_CURRENT_SOURCE_DIR}/include/secure_element/pkcs11
)
