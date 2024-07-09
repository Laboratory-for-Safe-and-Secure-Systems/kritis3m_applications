
option(ENABLE_TCP_ECHO_SERVER "Enable TCP echo server" ON)
option(ENABLE_TCP_CLIENT_STDIN_BRIDGE "Enable TCP client stdin bridge" ON)
option(ENABLE_TLS_PROXY "Enable TLS proxy" ON)

# Common files
add_subdirectory(common)

# TCP echo server application
if (ENABLE_TCP_ECHO_SERVER)
        add_subdirectory(tcp_echo_server)
endif()

# TCP client stdin bridge application
if (ENABLE_TCP_CLIENT_STDIN_BRIDGE)
        add_subdirectory(tcp_client_stdin_bridge)
endif()

# TLS proxy application
if (ENABLE_TLS_PROXY)
        add_subdirectory(tls_proxy)
endif()
