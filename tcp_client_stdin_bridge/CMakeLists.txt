
target_sources(${TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tcp_client_stdin_bridge.c
)

target_include_directories(${TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
