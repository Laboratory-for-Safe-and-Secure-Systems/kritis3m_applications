add_library(kritis3m_http_libs STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cJSON_Utils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cJSON.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_client.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_parser_url.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/linux_comp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_parser.c
)

target_include_directories(kritis3m_http_libs PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)




target_link_libraries(kritis3m_http_libs PRIVATE kritis3m_applications_common)