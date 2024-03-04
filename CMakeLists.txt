cmake_minimum_required(VERSION 3.18)

project(libder)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_compile_options(-fsanitize=address,undefined -fstrict-aliasing)
	add_link_options(-fsanitize=address,undefined -fstrict-aliasing)
endif()

add_subdirectory(libder)
add_subdirectory(derdump)
add_subdirectory(tests)
