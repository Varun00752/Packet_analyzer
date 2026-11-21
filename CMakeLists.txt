cmake_minimum_required(VERSION 3.16)
project(DeepPacketInspection VERSION 2.5 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optimization flags
if(MSVC)
    add_compile_options(/O2 /W4)
else()
    add_compile_options(-O3 -Wall -Wextra)
endif()

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Threads
find_package(Threads REQUIRED)

# Target 1: Core DPI Engine (Multi-threaded High-Performance Classifier)
add_executable(dpi_engine
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# Target 2: Basic Packet Analyzer (L2-L4 Packet Inspector)
add_executable(packet_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)
target_link_libraries(packet_analyzer PRIVATE Threads::Threads)
