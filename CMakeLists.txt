
option(ENABLE_ECHO_SERVER "Enable echo server" ON)
option(ENABLE_TCP_CLIENT_STDIN_BRIDGE "Enable TCP client stdin bridge" ON)
option(ENABLE_TLS_PROXY "Enable TLS proxy" ON)
option(ENABLE_NETWORK_TESTER "Enable network tester" ON)
SET (ENABLE_NETWORK_TESTER ON)

# Common files
add_subdirectory(common)


# Echo server application
if (ENABLE_ECHO_SERVER)
        add_subdirectory(echo_server)
endif()
# TCP client stdin bridge application
if (ENABLE_TCP_CLIENT_STDIN_BRIDGE)
        add_subdirectory(tcp_client_stdin_bridge)
endif()

# TLS proxy application
if (ENABLE_TLS_PROXY)
        add_subdirectory(tls_proxy)
endif()

# Network tester application
if (ENABLE_NETWORK_TESTER)
        add_subdirectory(network_tester)
endif()
add_subdirectory(http)