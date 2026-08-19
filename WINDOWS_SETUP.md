# Windows Setup Guide

This guide will help you build and run the DPI Engine on Windows. Follow these steps exactly.

---

## Option 1: Using Visual Studio (Recommended for Beginners)

### Step 1: Install Visual Studio

1. Download **Visual Studio 2022 Community** (free):
   - Go to: https://visualstudio.microsoft.com/downloads/
   - Click "Free download" under Community

2. Run the installer

3. When asked "What workloads to install", select:
   - ✅ **Desktop development with C++**
   
   ![Workload Selection](https://docs.microsoft.com/en-us/cpp/build/media/vscpp-concurrency-install-workload.png)

4. Click "Install" and wait (this takes 10-20 minutes)

### Step 2: Open the Project

1. Open Visual Studio 2022

2. Click **"Open a local folder"**

3. Navigate to the `packet_analyzer` folder and click "Select Folder"

4. Wait for Visual Studio to scan the files (bottom status bar shows progress)

### Step 3: Create a Build Configuration

1. In Solution Explorer (right side), right-click on the folder name

2. Click **"Add" → "New Item"**

3. Select **"C++ File (.cpp)"** and name it `CMakeSettings.json`

4. Replace the content with:

```json
{
  "configurations": [
    {
      "name": "x64-Release",
      "generator": "Ninja",
      "configurationType": "Release",
      "inheritEnvironments": ["msvc_x64_x64"],
      "buildRoot": "${projectDir}\\build\\${name}",
      "installRoot": "${projectDir}\\install\\${name}",
      "cmakeCommandArgs": "",
      "buildCommandArgs": "",
      "ctestCommandArgs": ""
    }
  ]
}
```

5. Save the file (Ctrl+S)

### Step 4: Build the Project

**Method A: Using CMake (if CMakeLists.txt works)**

1. Visual Studio should detect CMakeLists.txt automatically
2. Select **"Build" → "Build All"** from the menu
3. The executable will be in `build\x64-Release\`

**Method B: Manual Build (Recommended)**

1. Open **"View" → "Terminal"** (or press Ctrl+`)

2. In the terminal, type:

```cmd
cl /EHsc /std:c++17 /O2 /I include /Fe:PacketInspector.exe ^
    src\main.cpp ^
    src\packet_parser.cpp ^
    src\pcap_reader.cpp ^
    src\packet_source.cpp ^
    src\live_capture_source.cpp ^
    src\sni_extractor.cpp ^
    src\dns_parser.cpp ^
    src\http_parser.cpp ^
    src\types.cpp ^
    src\fast_path.cpp ^
    src\dpi_engine.cpp ^
    src\connection_tracker.cpp ^
    src\rule_manager.cpp ^
    src\stats_collector.cpp ^
    ws2_32.lib
```

3. If successful, you'll see `PacketInspector.exe` in the folder.

### Step 5: Run the Program

```cmd
:: 1. List available network interfaces
PacketInspector.exe --list-interfaces

:: 2. Run real-time live capture (Requires Npcap)
PacketInspector.exe --interface 1

:: 3. Run offline PCAP analysis
PacketInspector.exe --pcap test_dpi.pcap output.pcap
```

---

## Option 2: Using MinGW-w64 (GCC for Windows)

### Step 1: Install MSYS2 & Compiler

1. Download MSYS2 from: https://www.msys2.org/
2. Install to `C:\msys64` and open **MSYS2 UCRT64** or **MSYS2 MINGW64**.
3. Install compiler and tools:
```bash
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-ninja mingw-w64-ucrt-x86_64-cmake
```

### Step 2: Build the Project (CMake or g++)

**Using CMake + Ninja (Recommended):**
```powershell
cmake -B build -S . -G "Ninja"
cmake --build build
```

**Or Direct g++ Build:**
```powershell
g++ -std=c++17 -O2 -I include -o PacketInspector.exe `
    src/main.cpp src/packet_parser.cpp src/pcap_reader.cpp `
    src/packet_source.cpp src/live_capture_source.cpp `
    src/sni_extractor.cpp src/dns_parser.cpp src/http_parser.cpp `
    src/types.cpp src/fast_path.cpp src/dpi_engine.cpp `
    src/connection_tracker.cpp src/rule_manager.cpp `
    src/stats_collector.cpp -lws2_32
```

### Step 3: Run

```powershell
# List network interfaces
.\PacketInspector.exe --list-interfaces

# Live capture on interface #1
.\PacketInspector.exe --interface 1

# Offline PCAP mode
.\PacketInspector.exe --pcap test_dpi.pcap output.pcap
```

---

## Option 3: Using WSL (Windows Subsystem for Linux)

WSL lets you run Linux inside Windows - easiest if you're comfortable with Linux.

### Step 1: Install WSL

1. Open **PowerShell as Administrator**:
   - Press `Win`, type "PowerShell"
   - Right-click → "Run as administrator"

2. Run:
   ```powershell
   wsl --install
   ```

3. Restart your computer when prompted

4. After restart, Ubuntu will open automatically
   - Create a username and password when asked

### Step 2: Install Build Tools

In the Ubuntu terminal:

```bash
sudo apt update
sudo apt install -y build-essential g++
```

### Step 3: Navigate to Project

Your Windows files are accessible at `/mnt/c/`:

```bash
# If your project is at C:\Users\YourName\Downloads\packet_analyzer
cd /mnt/c/Users/YourName/Downloads/packet_analyzer
```

### Step 4: Build

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Step 5: Run

```bash
./dpi_engine test_dpi.pcap output.pcap
```

---

## Option 4: Using Visual Studio Code

### Step 1: Install VS Code

1. Download from: https://code.visualstudio.com/
2. Install with default options

### Step 2: Install Extensions

1. Open VS Code
2. Click Extensions icon (left sidebar) or press `Ctrl+Shift+X`
3. Search and install:
   - **C/C++** (by Microsoft)
   - **C/C++ Extension Pack** (by Microsoft)

### Step 3: Install a Compiler

Follow **Option 2** above to install MinGW-w64, then continue here.

### Step 4: Open the Project

1. **File → Open Folder**
2. Select the `packet_analyzer` folder

### Step 5: Create Build Task

1. Press `Ctrl+Shift+P`
2. Type "Tasks: Configure Task" and select it
3. Select "Create tasks.json file from template"
4. Select "Others"
5. Replace content with:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Build DPI Engine",
            "type": "shell",
            "command": "g++",
            "args": [
                "-std=c++17",
                "-O2",
                "-I", "include",
                "-o", "dpi_engine.exe",
                "src/dpi_mt.cpp",
                "src/pcap_reader.cpp",
                "src/packet_parser.cpp",
                "src/sni_extractor.cpp",
                "src/types.cpp"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "problemMatcher": ["$gcc"]
        }
    ]
}
```

6. Save the file

### Step 6: Build

Press `Ctrl+Shift+B` to build

### Step 7: Run

Open terminal in VS Code (`Ctrl+``) and run:

```cmd
.\dpi_engine.exe test_dpi.pcap output.pcap
```

---

## Troubleshooting

### Error: 'g++' is not recognized

**Cause:** MinGW not installed or not in PATH

**Fix:**
1. Make sure you installed MinGW-w64 (Option 2, Step 1)
2. Make sure you added to PATH (Option 2, Step 2)
3. Restart your computer
4. Open NEW terminal and try again

### Error: 'cl' is not recognized

**Cause:** Visual Studio compiler not in PATH

**Fix:**
1. Open "Developer Command Prompt for VS 2022" (search in Start Menu)
2. Navigate to project folder
3. Run the build command from there

### Error: Cannot find include file

**Cause:** Wrong directory or missing -I flag

**Fix:**
Make sure you're in the `packet_analyzer` folder:
```cmd
cd C:\full\path\to\packet_analyzer
dir include
```
You should see the .h files listed.

### Error: undefined reference to `std::thread`

**Cause:** Threading library not linked (MinGW)

**Fix:** Add `-pthread` flag:
```cmd
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine.exe ...
```

### Program runs but crashes immediately

**Cause:** Missing input file

**Fix:** Make sure test_dpi.pcap exists:
```cmd
dir test_dpi.pcap
```

If missing, create it:
```cmd
python generate_test_pcap.py
```

(Requires Python installed)

### Error: Cannot open output file

**Cause:** Permission denied or file in use

**Fix:** 
1. Close any program that might have output.pcap open
2. Try a different output filename:
   ```cmd
   dpi_engine.exe test_dpi.pcap result.pcap
   ```

---

## Quick Reference

### Build Commands Summary

| Method | Command |
|--------|---------|
| **Visual Studio (cl)** | `cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe src\dpi_mt.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp` |
| **MinGW (g++)** | `g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp` |
| **WSL/Linux** | `g++ -std=c++17 -pthread -O2 -I include -o dpi_engine src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp` |

### Run Commands

```cmd
# Basic run
dpi_engine.exe input.pcap output.pcap

# With blocking
dpi_engine.exe input.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50

# Custom thread count
dpi_engine.exe input.pcap output.pcap --lbs 4 --fps 4
```

---

## Getting Wireshark Captures

To test with real traffic:

1. Download Wireshark: https://www.wireshark.org/download.html

2. Install and open Wireshark

3. Select your network interface (usually "Wi-Fi" or "Ethernet")

4. Browse some websites for 30 seconds

5. Press the red square to stop capture

6. **File → Save As** → Choose "Wireshark/tcpdump/... - pcap"

7. Save as `my_capture.pcap`

8. Run DPI engine on it:
   ```cmd
   dpi_engine.exe my_capture.pcap filtered.pcap
   ```

---

## Need Help?

If you're stuck:

1. Make sure you followed EVERY step (don't skip any!)
2. Check the Troubleshooting section above
3. Try WSL (Option 3) - it's the most reliable
4. Google the exact error message

Good luck! 🚀
