
option(ENABLE_ECHO_SERVER "Enable echo server" ON)
option(ENABLE_TCP_CLIENT_STDIN_BRIDGE "Enable TCP client stdin bridge" ON)
option(ENABLE_TLS_PROXY "Enable TLS proxy" ON)
option(ENABLE_NETWORK_TESTER "Enable network tester" ON)
option(ENABLE_HTTP_LIBS "Enable HTTP(S) libraries" ON) # required for Scale Service and QUEST lib
option(ENABLE_MANAGEMENT "Enable Scale management" ON)
option(ENABLE_QUEST_LIB "Enable QUEST lib" ON)


# Generate the configuration file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/kritis3m_application_config.h.in kritis3m_application_config.h)


# Common files
add_subdirectory(common)

# Each consumer of any applications must link against this common library. Hence,
# we can add the include directory for the created config file via this target.
target_include_directories(kritis3m_applications_common PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

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

# HTTP(S) Library
if(ENABLE_HTTP_LIBS)
        add_subdirectory(http_lib)
endif()

# Scale management
if (ENABLE_MANAGEMENT)
        add_subdirectory(management_service)
endif()

# KRITIS3M QUEST lib
if (ENABLE_QUEST_LIB)
        add_subdirectory(quest_lib)
endif()