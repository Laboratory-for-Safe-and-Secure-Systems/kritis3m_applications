
# Define the library
add_library(kritis3m_applications_http STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_client.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_parser_url.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/http_parser.c
)

# Public include directories
target_include_directories(kritis3m_applications_http PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)


# Link the common KRITIS3M application library
target_link_libraries(kritis3m_applications_http PRIVATE kritis3m_applications_common)

# Link the library to the main target
target_link_libraries(${TARGET} PRIVATE kritis3m_applications_http)


