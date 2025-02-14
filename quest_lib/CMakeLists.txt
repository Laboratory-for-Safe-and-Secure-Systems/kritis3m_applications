# Specify the minimum version of CMake required
cmake_minimum_required(VERSION 3.22)

# Set the project name and language
project(QUEST C)

# Set the version of the library
set(PROJECT_VERSION 1.0.0)

# In case the QKD line does not operate correctly the library can inject a temporary key
option(FALLBACK_PSK "Inject a hardcoded PSK into the http_cb" OFF)

# Add the library sources
add_library(kritis3m-quest STATIC
  src/kritis3m_http_request.c 
  src/quest.c
)

# set compile definition of FALLBACK_PSK option if activated
if (FALLBACK_PSK)
    target_compile_definitions(kritis3m-quest PRIVATE TMP_KEY)
endif()

# Include public headers for `library`
target_include_directories(kritis3m-quest
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/kritis3m-http-libs>
)

# Link against the kritis3m-http-libs library
target_link_libraries(kritis3m-quest PUBLIC kritis3m-http-libs)

# Link against the kritis3m_applications_common
target_link_libraries(kritis3m-quest PUBLIC kritis3m_applications_common)
