
target_sources(${TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/networking.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/logging.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/poll_set.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/wolfssl.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tls_echo_server.c
)

target_include_directories(${TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
