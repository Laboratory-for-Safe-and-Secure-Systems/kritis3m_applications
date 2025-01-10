# Management Service

## Concept
The management client serves as the control plane implementation for interacting with the control server. Its primary objective is to receive configurations from the server, which are then used to configure and launch security applications.

### Architecture

The management client maintains two threads:

`./management_service/service/src/kritis3m_scale_service.c`
- the kritis3m_service thread is responsible for the communication with the control server and certificate management.

`./management_service/service/src/application_manager.c`
- the kritis3m_application_manager is responsible to start the kritis3m_applications (reverse-/forward proxy) based on the retrieved configurations

Both threads can interact with each other, using ipc via unix(linux)/tcp(windows) socketpairs.

**Current State**:
The `kritis3m_service` module communicates with the control server using HTTPS. At startup, the control server is queried only once. As a result, updates on the server are not automatically propagated to the client. The configurations received from the server are in JSON format and are stored on the file system as `primary.json`. Before the security applications are started, the content of `primary.json` is parsed into the `Systemconfiguration` structure.

The endpoint configurations for the proxy applications, which define the key exchange (KEX) method and signature mode, are based on the `Cryptoprofile` structure. Currently, only one type of certificates can be used for all applications. These certificate types are defined in the `crypto_identity` structure.

**Planned Changes**:
To enable dynamic updates from the control server, the HTTPS-based control plane protocol will be replaced by a WebSocket connection. This will maintain an open connection to the server, allowing real-time updates to be fetched.

**Planned Update Process**:
The update process will be transaction-based. When new configurations become available on the server, all clients will retrieve the latest configurations simultaneously. Once all clients confirm to the server that the configurations can be applied, the application manager will be restarted with the new configurations.

To support this process, two configurations will be maintained simultaneously: `primary.json` and `secondary.json`. To support this, the structure `ConfigurationManager` maintains both configurations. One configuration will always be active and in use by the application manager, while the other will remain inactive and be used for receiving updates.

If the new configurations cannot be applied, a rollback to the previous configuration will be triggered. In the case of a successful update, the application manager will be shut down and restarted with the updated configurations.

**Planned Crypto Identities**:
To maintain multiple kritis3m applications, with different certificate types. Endpoints are matched to certain `crypto_identities`(production, management, management_service). Each crypto identity owns certificates in its own identity folder.
As part of future work, `crypto_identities` are fetched from the control server. Within the configuration update process, it's the management clients objective to call the PKI to obtain the certificates. For instance if the matching certificates to a certain `crypto_identity` can't be fetched from the PKI, a rollback will initiated.