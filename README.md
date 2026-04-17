# Quanta Mobile Core

Native Android JNI bridge for QuantaChain's post-quantum cryptography. 
This library is built as a C-dynamic library (`cdylib`) to provide Kotlin and React Native applications with direct hardware access to Falcon-512 signatures, entirely bypassing WebAssembly engine limitations.

## Requirements

To build the native bindings for ARM mobile devices, you must have the Android NDK installed and configured.

- Rust 1.70+
- Android NDK (r25c recommended)
- `cargo-ndk`

## Setup and Building (Linux / WSL)

If you do not have the Android SDK globally installed on your system, you can download the standalone NDK locally and use it to cross-compile.

1. Download and extract the NDK (r25c):
```bash
wget https://dl.google.com/android/repository/android-ndk-r25c-linux.zip
unzip android-ndk-r25c-linux.zip
```

2. Export the NDK path to your environment:
```bash
export ANDROID_NDK_HOME=$(pwd)/android-ndk-r25c
```

3. Install the Rust cross-compilation toolchains:
```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

4. Build the binary for modern Android (ARM64):
```bash
cargo ndk -t arm64-v8a build --release
```

## Integrating with Android

The compiled binary object will be located at `target/aarch64-linux-android/release/libquanta_mobile_core.so`.

Copy this specific file into your Android project under the `app/src/main/jniLibs/arm64-v8a/` directory. You can then interface with the exposed JNI bindings using the exact package path `com.quanta.mobile.crypto.NativeCrypto`.
