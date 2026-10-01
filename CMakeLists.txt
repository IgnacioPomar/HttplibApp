cmake_minimum_required(VERSION 3.23)

project(HttplibApp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(HTTPLIBAPP_BUILD_TESTS "Build the unit tests" OFF)

# cpp-httplib. The TLS backend (none, wolfSSL or OpenSSL) is chosen by whoever provides it:
# CPPHTTPLIB_WOLFSSL_SUPPORT / CPPHTTPLIB_OPENSSL_SUPPORT come with the httplib target
find_package(httplib REQUIRED)
# Crypto for JWT
find_package(botan REQUIRED)

add_library(HttplibApp
    src/Jwt.cpp
    src/Route.cpp
)
add_library(HttplibApp::HttplibApp ALIAS HttplibApp)

target_include_directories(HttplibApp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(HttplibApp PUBLIC httplib::httplib PRIVATE botan::botan)

# Before 1.0 a minor version may break the ABI: libHttplibApp.so.0.1 -> libHttplibApp.so.0.1.0
if(PROJECT_VERSION_MAJOR EQUAL 0)
    set(HTTPLIBAPP_SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})
else()
    set(HTTPLIBAPP_SOVERSION ${PROJECT_VERSION_MAJOR})
endif()

# Only the symbols marked with HAPP_API are exported from the shared library
set_target_properties(HttplibApp PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${HTTPLIBAPP_SOVERSION}
)
if(BUILD_SHARED_LIBS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Neither export the symbols of the static libraries linked in (Botan)
    target_link_options(HttplibApp PRIVATE LINKER:--exclude-libs,ALL)
endif()

# Generated HAPP_API / HAPP_LOCAL / HAPP_DEPRECATED: empty for a static library, export/import for a shared one
# (HttplibApp_EXPORTS is defined by CMake when building the shared library)
include(GenerateExportHeader)
generate_export_header(HttplibApp
    BASE_NAME HAPP
    EXPORT_MACRO_NAME HAPP_API
    NO_EXPORT_MACRO_NAME HAPP_LOCAL
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/HttplibApp/httplib_app_exportcfg.h
)

install(TARGETS HttplibApp)
install(DIRECTORY include/ ${CMAKE_CURRENT_BINARY_DIR}/include/ DESTINATION include)

if(HTTPLIBAPP_BUILD_TESTS)
    enable_testing()

    find_package(Catch2 3 REQUIRED)

    add_executable(HttplibAppTester
        test/001_Route.cpp
        test/002_Jwt.cpp
    )
    target_link_libraries(HttplibAppTester PRIVATE HttplibApp Catch2::Catch2WithMain)

    include(Catch)
    catch_discover_tests(HttplibAppTester PROPERTIES TIMEOUT 60)
endif()
