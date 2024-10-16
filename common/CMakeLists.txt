
# Define the library
add_library(kritis3m_applications_common STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/networking.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/logging.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/poll_set.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/timing_metrics.c
)

# Add the getopt implementation for Windows if MSVC is used
if(MSVC)
        target_sources(kritis3m_applications_common PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/win_compat/getopt.c
        )
endif()

# Public include directories
target_include_directories(kritis3m_applications_common PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if (MSVC)
        target_include_directories(kritis3m_applications_common PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include/win_compat
        )
endif()

# Link the library with the required libraries
if(NOT MSVC)
        target_link_libraries(kritis3m_applications_common
                m # Timing metrics need the math library
        )
endif()
if(WIN32)
        target_link_libraries(kritis3m_applications_common wsock32 ws2_32)
endif()
