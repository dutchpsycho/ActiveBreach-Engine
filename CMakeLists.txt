cmake_minimum_required(VERSION 3.15)

project(MDSECHookBypass VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_GENERATOR_PLATFORM x64)

set(SOURCES
    src/loader.cpp
    src/master.cpp
    src/stub.cpp
	src/IC.c
)

set(HEADERS
    src/framework.hpp
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})
target_include_directories(${PROJECT_NAME} PRIVATE src/)
target_link_libraries(${PROJECT_NAME} PRIVATE kernel32.lib user32.lib)