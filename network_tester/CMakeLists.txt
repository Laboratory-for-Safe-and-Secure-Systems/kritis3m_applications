
# Define the library
add_library(kritis3m_applications_network_tester STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/network_tester.c
)

# Public include directories
target_include_directories(kritis3m_applications_network_tester PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link the common KRITIS3M application library
target_link_libraries(kritis3m_applications_network_tester PRIVATE kritis3m_applications_common)
