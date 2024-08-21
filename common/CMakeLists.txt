
# Define the library
add_library(kritis3m_applications_common STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/networking.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/logging.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/poll_set.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/timing_metrics.c
)

# Public include directories
target_include_directories(kritis3m_applications_common PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
