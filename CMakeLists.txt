cmake_minimum_required (VERSION 3.8)

set(PROJECT_NAME "FPHE")
    project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
add_executable(${PROJECT_NAME} ${SOURCES})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
endif()

set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/CPET_SEAL/install/lib/cmake/SEAL-4.1")

find_package(SEAL 4.1 REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE SEAL::seal) 
