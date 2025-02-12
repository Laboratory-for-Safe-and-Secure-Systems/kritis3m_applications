# Specify the minimum version of CMake required
cmake_minimum_required(VERSION 3.22)

# Set the project name and language
project(QUEST C)

include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_language(C)

# Necessary to allow FetchContent_Populate
if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
endif()

# Set the version of the library
set(PROJECT_VERSION 1.0.0)

# Make sure all libraries are installed in the lib directory (not lib64)
set(CMAKE_INSTALL_LIBDIR "lib")

########################################################################
#                               OPTIONS                                #
######################################################################## 

# Add an option for building a shared or static library
option(BUILD_SHARED_LIBS "Build as a shared library" ON)
# Can be activated to enable Info Prints in the library during usage.
option(VERBOSE_PRINT "Activate printing of further information in addition to error messages" ON)

# Set the output directories for libraries and executables
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Add kritis3m-quest library subdirectory
add_subdirectory(library)

# Link against the kritis3m-http-libs library
target_link_libraries(kritis3m-quest PRIVATE kritis3m-http-libs)

# Add a preprocessor definition to indicate that we are building the library
# This is required to distinguish between building the library and using it
# in an application within the header files.
target_compile_definitions(kritis3m-quest PRIVATE "BUILDING_KRITIS3M_QUEST")
if(BUILD_SHARED_LIBS)
        target_compile_definitions(kritis3m-quest PUBLIC "BUILDING_KRITIS3M_QUEST_SHARED")
endif()

install(TARGETS kritis3m-quest
        EXPORT kritis3m-quest-export
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers from the kritis3m-quest lib
install(DIRECTORY library/include/ DESTINATION include/kritis3m-quest)

# Install CMake configuration files so other CMake projects can find this library
install(EXPORT kritis3m-quest-export
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m-quest
        FILE kritis3m-quest-export.cmake
)
export(EXPORT kritis3m-quest-export
       FILE kritis3m-quest-export.cmake
)

include(CMakePackageConfigHelpers)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m-quest-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/kritis3m-quest-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m-quest
        NO_SET_AND_CHECK_MACRO
        NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kritis3m-quest-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m-quest
)