# PSP PRX Decrypter - Rust Port

**A secure and modern Rust port** of the classic PSP (PlayStation Portable) PRX/EBOOT.BIN decrypter based on the KIRK engine.

> Development fork / Active port

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

## Overview
This is a command-line tool designed to run on modern operating systems (Windows, macOS, Linux). It unpacks and decrypts Sony PSP executable files by software-emulating the original hardware cryptography engine. **Note: This is a PC tool, not a PSP homebrew application.**

## Features

- **Automatic encryption type detection** (tag parsing)
- Full support for **AES decryption** + KIRK engine
- **SHA1 integrity validation**
- Safe binary header parsing with zero-copy focus
- Strong emphasis on **memory safety** and modern Rust practices (minimal `unsafe`)
- Clean architecture with good separation of concerns

## Project Structure

```bash
src/
├── main.rs                 # CLI entry point
├── headers.rs              # Binary header parsing
├── prx_decrypt.rs          # Main decryption logic
├── kirk_lib/               # KIRK engine implementation
├── keys.rs                 # Key management
└── utils.rs                # Helpers
```

## Quick Start
### Build & Run
```bash
# Build optimized version
cargo build --release

# Run
./target/release/psp-prx-decrypter <path_to_prx_or_eboot_file>
```

## Run Tests
```bash
cargo test
```

### Motivation
This project started as a learning exercise in reverse engineering and low-level programming. The goal was to take an existing C++ tool and rebuild it in modern, safe Rust while maintaining (or improving) performance and adding better error handling.



### Roadmap
 - Complete support for all tag types
 - More comprehensive unit and integration tests with real files
 - Richer CLI (progress bar, batch processing, output options)
 - Library mode (usable as a crate)
 - Performance benchmarks vs original C++ version