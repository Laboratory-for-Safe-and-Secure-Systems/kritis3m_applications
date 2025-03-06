
/***********************************************************************************/
/*              Quantum-Key Exchange Server Transaction (QUEST) library            */
/***********************************************************************************/

The QUEST library is used to request information from a Quantum Key Distribution 
(QKD) Key Management System (KMS). Among these information it is possible to re-
quest the latest generated key using HTTP_KEY_NO_ID in the request_type, a specific 
key by using HTTP_KEY_WITH_ID and a key_ID passed to the quest_transction or request 
the current status of the QKD line by specifying HTTP_STATUS in the request_type.

┌──────────────────────────┐
│quest_configuration       │
├──────────────────────────┤
│+ verbose : bool          │
│+ enable_secure_con : bool│
│__                        │ <---- quest_default_config()
│connection_info:          │
│+ hostname : char*        │
│+ hostport : char*        │
└──────────────────────────┘
              |
              | quest_setup_endpoint()
              v
┌────────────────────────────────┐
│quest_endpoint                  │
├────────────────────────────────┤
│+ verbose : bool                │
│__                              │
│connection_info:                │
│+ socket_fd : int               │
│+ hostname : char*              │
│+ hostport : char*              │
│+ IP_v4 : struct addrinfo*      │
│+ IP_str : char[]               │
│__                              │
│security_param:                 │
│+ enable_secure_con : bool      │
│+ client_endpoint : asl_endpoint│
└────────────────────────────────┘
              |
              | quest_setup_transaction()
              v
┌───────────────────────────────────────────┐
│quest_transaction                          │
├───────────────────────────────────────────┤
│+ endpoint : quest_endpoint*               │
│__                                         │
│security_param:                            │
│+ enable_secure_con : bool                 │
│+ tls_session : asl_session*               │
│__                                         │
│+ request_type : enum http_get_request_type│
│+ request_: http_request*                  │
│+ response : http_get_response*            │
│+ key_ID : char[]                          │
└───────────────────────────────────────────┘

As displayed in the diagram above, the QUEST library consists of three entities:

Initially the user can generate a quest_configuration by calling the function 
quest_default_config(). Subsequently the quest_configuration can be adjusted to the 
by specifying the desired hostname and hostport, as well as activating the secure 
connection and verbose flag. 

Using this configuration, the function quest_setup_endpoint() derives a connection 
endpoint, which contains further communication and security parameter. This endpoint 
can be active for multiple requests to the same QKD line and further contains the 
asl_endpoint containing the set of certificates for the HTTPS connection, if 
enable_secure_con is set to true.

Using the quest_endpoint parameters, the user can setup key or status requests by 
calling the function quest_setup_transaction(). This function starts the communi- 
cation procedure to the QKD line by establishing a TCP connection and generating the 
neccessary HTTP(S)-request and HTTP(S)-response objects.

By calling the function quest_send_request() the transaction is executed and the re- 
quest is sent to the QKD KMS. If everything is working correctly, the response object 
then contains the requested information. 
