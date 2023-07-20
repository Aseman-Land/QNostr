# Generated from qthttpserver.pro.

cmake_minimum_required(VERSION 3.15.0)

project(QNostr
    VERSION 6.0.0
    DESCRIPTION "Qt Nostr Client"
    HOMEPAGE_URL "https://aseman.io/"
    LANGUAGES CXX C
)

find_package(Qt6 ${PROJECT_VERSION} CONFIG REQUIRED COMPONENTS BuildInternals Core Network WebSockets)
find_package(OpenSSL REQUIRED)

qt_build_repo()
