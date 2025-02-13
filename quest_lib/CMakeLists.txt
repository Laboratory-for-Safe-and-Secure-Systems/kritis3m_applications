# Specify the minimum version of CMake required
cmake_minimum_required(VERSION 3.22)

# Set the project name and language
project(QUEST C)

# Set the version of the library
set(PROJECT_VERSION 1.0.0)

# Can be activated to enable Info Prints in the library during usage.
option(VERBOSE_PRINT "Activate printing of further information in addition to error messages" ON)
# In case the QKD line does not operate correctly the library can inject a temporary key
option(FALLBACK_PSK "Inject a hardcoded PSK into the http_cb" OFF)

# Include Headers from the include Folder
include_directories(
   include/
)

# Add the library sources
add_library(kritis3m-quest STATIC
  src/kritis3m_http_request.c 
  src/quest.c
)

# set compile definition of VERBOSE_PRINT option if activated
if (VERBOSE_PRINT)
    target_compile_definitions(kritis3m-quest PRIVATE VERBOSE)
endif()

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
target_link_libraries(kritis3m-quest PRIVATE kritis3m-http-libs)

