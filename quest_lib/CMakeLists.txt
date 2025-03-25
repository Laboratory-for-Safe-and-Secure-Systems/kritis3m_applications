# Specify the minimum version of CMake required
cmake_minimum_required(VERSION 3.22)

# Set the project name and language
project(QUEST C)

# Set the version of the library
set(PROJECT_VERSION 1.0.0)

# Add the library sources
add_library(kritis3m-quest STATIC
  src/kritis3m_http_request.c 
  src/kritis3m_http_response.c
  src/quest_endpoint.c
  src/quest_transaction.c
  src/quest.c
)

# Include public headers for `library`
target_include_directories(kritis3m-quest PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/kritis3m-http-libs>
)

# Private headers
target_include_directories(kritis3m-quest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/private_include
)

# Link against the kritis3m-http-libs library
target_link_libraries(kritis3m-quest PUBLIC kritis3m-http-libs)

# Link against the kritis3m_applications_common
target_link_libraries(kritis3m-quest PUBLIC kritis3m_applications_common)