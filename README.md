# KRITIS³M Applications

This repository contains code that is used from within multiple other repositories of the KRITIS³M research project.

**Disclaimer:** This repository can not be used on its own and must be consumed from another repository. See [kritis3m_pki](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_pki) or [kritis3m_tls_linux](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_tls_linux) as examples.

The code is split into various directories (please refer to the individual README files):
* [common](common/README.md): Common helper code for the applications (e.g., logging, file handling, networking)
* [echo_server](echo_server/README.md): TCP/TLS echo server
* l2_bridge: Legacy application, **not** used anymore
* [management_service](management_service/README.md): Application endpoints for interaction with the [KRITIS³M Scale management service](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_scale)
* [network_tester](network_tester/README.md): Application to test some Quality of Service (QoS) parameters of TCP/TLS endpoints
* [tcp_client_stdin_bridge](tcp_client_stdin_bridge/README.md): Simple TCP client with stdin/stout support (keyboard input)
* [tls_proxy](tls_proxy/README.md): Main KRITIS³M application for TLS forward and reverse proxies.

Using the following CMake variables, individual applications can be disabled (all are `ON` by default):
* `ENABLE_ECHO_SERVER`
* `ENABLE_TCP_CLIENT_STDIN_BRIDGE`
* `ENABLE_TLS_PROXY`
* `ENABLE_NETWORK_TESTER`
* `ENABLE_HTTP_LIBS`
* `ENABLE_MANAGEMENT`
* `ENABLE_QUEST_LIB`

Common code is always enabled.