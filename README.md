# PSP PRX Decrypter - Rust Port

**A secure and modern Rust port** of the classic PSP (PlayStation Portable) PRX/EBOOT.BIN decrypter based on the KIRK engine.

> Development fork / Active port

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

## Overview
This is a command-line tool designed to run on modern operating systems (Windows, macOS, Linux). It unpacks and decrypts Sony PSP executable files by software-emulating the original hardware cryptography engine. **Note: This is a PC tool, not a PSP homebrew application.**

### Status
The decryption tool is being refactored and It's currently fixing misc bugs. So after doing that stuff I'll present the full features available and it's structure.

### Motivation
This project started as a learning exercise in reverse engineering and low-level programming. The goal was to take an existing C++ tool and rebuild it in modern, safe Rust while maintaining (or improving) performance and adding better error handling.



