# CPP-PHP-Obfuscator

## Overview
CPP-PHP-Obfuscator is a C++ tool that encodes PHP code into base64 format, enhancing code confidentiality and making reverse engineering more challenging.

## Features
- Encode PHP code into base64 format
- Enhance code confidentiality and security
- Facilitate code obfuscation for PHP scripts

## Usage
1. Clone the repository: `git clone https://github.com/0x01x02x03/CPP-PHP-Obfuscator.git`
2. Compile the source code: `g++ -o obfuscator main.cpp -lssl -lcrypto`
3. Run the executable: `./obfuscator <path-to-your-php-file> [repetitions]`
   - Replace `<path-to-your-php-file>` with the path to your PHP file.
   - `[repetitions]` is an optional argument to specify the number of repetitions for encoding (default is 1).

## License
This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the [LICENSE](LICENSE) file for details.

## Contributors
- [0x01x02x03](https://github.com/0x01x02x03) - Author
