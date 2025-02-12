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

