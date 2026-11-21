@echo off
echo =========================================================
echo Compiling Deep Packet Inspection (DPI) Engine
echo =========================================================

g++ -std=c++17 -O3 -Iinclude src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp src/dpi_mt.cpp -o dpi_engine.exe

if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] Compilation successful: dpi_engine.exe created!
    echo Run: .\dpi_engine.exe test_dpi.pcap filtered.pcap
) else (
    echo [ERROR] Compilation failed. Ensure g++ C++17 compiler is in your PATH.
)
