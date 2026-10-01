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
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(HttplibApp PUBLIC httplib::httplib PRIVATE botan::botan)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(HttplibApp PUBLIC HAPP_DLL PRIVATE HTTPLIBAPP_EXPORTS)
endif()

install(TARGETS HttplibApp)
install(DIRECTORY include/ DESTINATION include)

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
