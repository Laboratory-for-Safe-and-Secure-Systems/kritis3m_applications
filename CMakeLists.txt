
option(ENABLE_ECHO_SERVER "Enable echo server" ON)
option(ENABLE_TCP_CLIENT_STDIN_BRIDGE "Enable TCP client stdin bridge" ON)
option(ENABLE_TLS_PROXY "Enable TLS proxy" ON)
<<<<<<< HEAD
<<<<<<< HEAD
option(ENABLE_HTTP "Enable HTTP" ON)
=======
=======
option(ENABLE_HTTP "Enable HTTP" ON)
>>>>>>> d0ce145 (added http libs and CMake integration)
option(ENABLE_NETWORK_TESTER "Enable network tester" ON)
>>>>>>> e8360e1 (Added network_tester as an application)

# Common files
add_subdirectory(common)

# Echo server application
if (ENABLE_ECHO_SERVER)
        add_subdirectory(echo_server)
endif()

option(ENABLE_HTTP "Enable HTTP" ON)
option(ENABLE_NETWORK_TESTER "Enable network tester" ON)

# TCP client stdin bridge application
if (ENABLE_TCP_CLIENT_STDIN_BRIDGE)
        add_subdirectory(tcp_client_stdin_bridge)
endif()

# TLS proxy application
if (ENABLE_TLS_PROXY)
        add_subdirectory(tls_proxy)
endif()

<<<<<<< HEAD
# Enable HTTP
if (ENABLE_HTTP)
        add_subdirectory(http)
endif()


=======
# Network tester application
if (ENABLE_NETWORK_TESTER)
        add_subdirectory(network_tester)
endif()
<<<<<<< HEAD
>>>>>>> e8360e1 (Added network_tester as an application)
=======

# Enable HTTP
if (ENABLE_HTTP)
        add_subdirectory(http)
endif()


>>>>>>> d0ce145 (added http libs and CMake integration)
