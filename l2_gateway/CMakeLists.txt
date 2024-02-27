
target_sources(${TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/l2_gateway.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/dtls_socket.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/udp_socket.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/packet_socket.c
)

target_include_directories(${TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
