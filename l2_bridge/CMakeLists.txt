
target_sources(${TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/l2_bridge.c
)

target_include_directories(${TARGET} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
