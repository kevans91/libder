file(GLOB derbuild_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_executable(derbuild ${derbuild_SOURCES})

target_include_directories(derbuild PRIVATE "${CMAKE_SOURCE_DIR}/libder")
target_link_libraries(derbuild der_static)
