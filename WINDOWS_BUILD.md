# Windows Visual Studio 2022 Build Guide

## Prerequisites

- Visual Studio 2022 (17.x or later) with C++ workload
- vcpkg already installed at `D:\003_DEV\Libraries\vcpkg`
- Ninja or your preferred CMake generator

## Setup Steps

### 1. Install OpenLDAP via vcpkg (one-time)

Run in **Developer PowerShell** or **Developer Command Prompt**:

```powershell
D:\003_DEV\Libraries\vcpkg\vcpkg.exe install openldap:x64-windows
```

This installs OpenLDAP headers and libraries into vcpkg's x64-windows triplet directory, making them discoverable by CMake.

### 2. Open Project in Visual Studio 2022

1. **File → Open → Folder** → select project directory
2. VS2022 automatically detects `CMakePresets.json`
3. In the **CMake Presets** dropdown (top toolbar), select:
   - `windows-x64-debug` for Debug build
   - `windows-x64-release` for Release build

### 3. Configure and Build

1. **Project → Delete Cache and Reconfigure** (or let VS auto-configure on first open)
2. **Build → Build All** (Ctrl+Shift+B)

Expected output: Builds all targets without errors:
- `osslCrypto.lib` (static library)
- `demo.exe`
- `load_certs.exe`
- `ldap_demo.exe`
- `ocsp_demo.exe`
- `crypto_demo.exe`

### 4. Run Tests

From **Build → Run** menu or run directly:

```cmd
out\build\x64-Debug\crypto_demo.exe test_certs\rsa2048_sha256.pem test_certs\rsa2048_sha256.key
out\build\x64-Debug\crypto_demo.exe test_certs\ec_prime256v1_sha256.pem test_certs\ec_prime256v1_sha256.key
```

Expected output: `All Tests Passed ✓`

## CMakePresets.json Details

The project includes two Windows presets in `CMakePresets.json`:

| Preset | Generator | Build Type | Output Path |
|--------|-----------|-----------|-------------|
| `windows-x64-debug` | Ninja | Debug | `out/build/x64-Debug` |
| `windows-x64-release` | Ninja | Release | `out/build/x64-Release` |

Both presets:
- Point to vcpkg toolchain at `D:\003_DEV\Libraries\vcpkg\scripts\buildsystems\vcpkg.cmake`
- Target `x64-windows` triplet
- Automatically discover OpenSSL and OpenLDAP via vcpkg

## Linux Still Supported

The `CMakePresets.json` includes a Linux preset. On Linux, configure with:

```bash
cmake --preset linux-x64-debug
cmake --build --preset linux-x64-debug
```

Or use the traditional CMake workflow:

```bash
cd build
cmake ..
make
```

## Troubleshooting

### CMake Configure Fails: "LDAP_LIB-NOTFOUND"

**Cause:** OpenLDAP not installed in vcpkg

**Fix:**
```powershell
D:\003_DEV\Libraries\vcpkg\vcpkg.exe install openldap:x64-windows
```

Then in VS2022: **Project → Delete Cache and Reconfigure**

### CMake Configure Fails: "OpenSSL not found"

**Cause:** vcpkg toolchain not set correctly

**Check:** In `CMakePresets.json`, the `toolchainFile` should point to:
```
D:/003_DEV/Libraries/vcpkg/scripts/buildsystems/vcpkg.cmake
```

If your vcpkg is at a different location, update this path in the preset before configuring.

### Compiler Warnings: "C4996"

These are normal MSVC deprecation warnings for POSIX functions. They are **suppressed** by the CMake definition `_CRT_SECURE_NO_WARNINGS` added in this update.

If you still see them, verify the CMakeCache.txt contains:
```
osslCrypto_COMPILE_DEFINITIONS:STRING=_CRT_SECURE_NO_WARNINGS;WIN32_LEAN_AND_MEAN;NOMINMAX;_WIN32_WINNT=0x0601
```

## Key Changes in This Update

### Files Modified

1. **CMakeLists.txt**
   - Replaced hard-coded Linux LDAP path with platform-conditional discovery
   - Added `if(WIN32)` block that uses `find_path`/`find_library` for vcpkg
   - Kept Linux Homebrew fallback in `else()` block
   - Added MSVC compile definitions to suppress C4996 warnings and avoid macro conflicts

2. **osslOcspClient.cpp**
   - Fixed bare `gmtime_r()` call at line 419 with `#if defined(_WIN32)` guard
   - Uses `gmtime_s()` on Windows (reversed argument order)

3. **ocsp_demo.cpp**
   - Fixed bare `gmtime_r()` call at line 10 with the same guard pattern

### Files Created

4. **vcpkg.json**
   - Declares dependencies: openssl, openldap
   - Enables vcpkg manifest mode for automatic dependency installation

5. **CMakePresets.json**
   - Defines Windows x64-Debug/Release and Linux presets
   - Integrates with VS2022 native CMake support
   - Points to your existing vcpkg installation

## Building Without Visual Studio

If you prefer command-line CMake:

```powershell
cmake --preset windows-x64-debug
cmake --build --preset windows-x64-debug
```

This generates and builds using Ninja (ensure Ninja is in PATH or installed via vcpkg).
