# file-manager
# Operating System Course Project
Made by group of 3 people

This project implements various file manipulation and encryption/decryption functionalities using multithreading and synchronization mechanisms in C. Below is an overview of the project and instructions on how to use it.

## Overview

The project consists of several functionalities implemented through command-line commands:

- **File Management**: Creating, deleting, and renaming files within a specified directory.
- **Encryption**: Encrypting files using a simple XOR encryption method and storing hash values.
- **Decryption**: Decrypting previously encrypted files and retrieving stored hash values.
- **Sorting**: Sorting files alphabetically within a directory.
- **Keyword Indexing**: Creating an index of keywords found in text files and allowing searching through them.

## Requirements

To compile and run this project, ensure you have the following installed:

- **GCC**: The GNU Compiler Collection for compiling C programs.
- **Linux Environment**: This project assumes a Linux environment due to the use of system-specific libraries and commands (`pthread`, `semaphore`, `mmap`, etc.).

## Commands and Usage

### Compilation

Compile the project using GCC:

```bash
gcc project.c -o project -pthread
```

### Commands

The project supports the following commands:

- **Create File**: `-c <directory>` - Creates a new file in the specified directory.
- **Delete File**: `-del <directory>` - Deletes a file in the specified directory.
- **Rename File**: `-r <directory>` - Renames a file in the specified directory.
- **Encryption**: `-e <directory>` - Encrypts a file using XOR encryption and stores hash values.
- **Decryption**: `-d <directory>` - Decrypts a previously encrypted file and retrieves stored hash values.
- **Sorting**: `-s <directory>` - Sorts files alphabetically within the specified directory.
- **Keyword Indexing**: `-p <directory>` - Creates an index of keywords found in text files and allows searching.

### Examples

Compile the project:

```bash
gcc project.c -o project -pthread
```

Create a new file:

```bash
./project -c /path/to/directory
```

Encrypt a file:

```bash
./project -e /path/to/file.txt
```

Decrypt a file:

```bash
./project -d /path/to/encrypted_file.txt
```

Sort files alphabetically:

```bash
./project -s /path/to/directory
```

Create a keyword index:

```bash
./project -p /path/to/directory
```

## Notes

- **Concurrency**: The project utilizes multithreading (`pthread`) and synchronization (`mutex`, `semaphore`) for concurrent operations.
- **Error Handling**: Error messages are displayed for file operations and encryption/decryption failures.
- **Compatibility**: Ensure you are running this project on a Linux system due to system-specific commands and libraries used.

---
