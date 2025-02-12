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

########################################################################
#                               OPTIONS                                #
######################################################################## 

# Can be activated to enable Info Prints in the library during usage.
option(VERBOSE_PRINT "Activate printing of further information in addition to error messages" ON)

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
