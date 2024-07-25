
# Define the library
add_library(kritis3m_applications_proxy STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy_backend.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy_management.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy_connection.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/proxy_api.c
)

# Public include directories
target_include_directories(kritis3m_applications_proxy PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Private include directories
target_include_directories(kritis3m_applications_proxy PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

# Link the common KRITIS3M application library
target_link_libraries(kritis3m_applications_proxy PRIVATE kritis3m_applications_common)
