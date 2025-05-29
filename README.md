# Caesar Cipher Tool (ShiftingGUI)

A sleek, minimalist, and tech-inspired Python GUI application for encrypting, decrypting, and analyzing text using the Caesar cipher and related classical ciphers.

## Features

- **Encrypt and Decrypt** using the Caesar cipher (supports upper/lowercase and punctuation)
- **Brute Force**: Try all possible Caesar keys and display results
- **Frequency Analysis**: See letter frequency counts as text
- **Frequency Chart**: Visualize letter frequencies with a bar chart (requires `matplotlib`)
- **Detect Key**: Automatically guess the most likely Caesar key for a ciphertext
- **ROT13**: Apply the ROT13 cipher (a Caesar cipher with key 13)
- **Atbash**: Apply the Atbash cipher (alphabet reversal)
- **Modern GUI**: Styled with a dark theme and monospace font for a terminal/coding feel
- **Status Bar**: See operation feedback at the bottom

## How to Use

1. **Install requirements**  
   This program requires `matplotlib` for the frequency chart:
   ```bash
   pip install matplotlib
   ```

2. **Run the program**
   ```bash
   python ShiftingGUI.py
   ```

3. **Main operations**
   - Enter your text in the "Input Text" box.
   - Enter a key (0-25) for Caesar cipher operations.
   - Click **Encrypt** or **Decrypt** to process your text.
   - Use **Brute Force** to try all keys.
   - Use **Frequency Analysis** to see letter counts as text.
   - Use **Frequency Chart** to see a bar chart of letter frequencies.
   - Use **Detect Key** to let the program guess the most likely key.
   - Try **ROT13** or **Atbash** for other classical ciphers.

## Educational Value

This tool was created to help me (and others) be more efficient in cryptography classes and exercises.  
It demonstrates:
- Classical cipher mechanics
- Brute-force attacks
- Frequency analysis and cryptanalysis basics
- The importance of key secrecy and cipher strength


*Created for educational purposes and cryptography practice.*
