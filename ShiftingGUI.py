import tkinter as tk
import string
from collections import Counter
from tkinter import scrolledtext, ttk
import re
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

LETTERS = string.ascii_lowercase

def encrypt(plaintext, key):
    result = ""
    for ch in plaintext:
        if ch.islower():
            idx = LETTERS.find(ch)
            result += LETTERS[(idx + key) % 26]
        elif ch.isupper():
            idx = LETTERS.upper().find(ch)
            result += LETTERS.upper()[(idx + key) % 26]
        else:
            result += ch
    return result

def decrypt(cyphertext, key):
    result = ""
    for ch in cyphertext:
        if ch.islower():
            idx = LETTERS.find(ch)
            result += LETTERS[(idx - key) % 26]
        elif ch.isupper():
            idx = LETTERS.upper().find(ch)
            result += LETTERS.upper()[(idx - key) % 26]
        else:
            result += ch
    return result

def brute_force(cyphertext):
    results = []
    for key in range(1, 26):
        results.append(f"Key {key:2}: {decrypt(cyphertext, key)}")
    return "\n".join(results)

def frequency_analysis(text):
    filtered = [ch.lower() for ch in text if ch.isalpha()]
    freq = Counter(filtered)
    results = []
    for letter, count in freq.most_common():
        results.append(f"{letter}: {count}")
    return "\n".join(results)

def detect_key():
    ciphertext = text_input.get("1.0", "end-1c")
    if not ciphertext.strip():
        status_bar.config(text="Error: No text to analyze")
        return
    
    common_words = ['the', 'and', 'that', 'have', 'for', 'not', 'with', 'you', 'this', 'but']
    
    best_key = 0
    best_score = 0
    
    for key in range(1, 26):
        decrypted = decrypt(ciphertext, key)
        clean_text = re.sub(r'[^\w\s]', '', decrypted.lower())
        words = clean_text.split()
        
        score = sum(1 for word in words if word in common_words)
        
        if score > best_score:
            best_score = score
            best_key = key
    
    entry_key.delete(0, tk.END)
    entry_key.insert(0, str(best_key))
    status_bar.config(text=f"Detected most likely key: {best_key} (Found {best_score} common word matches)")

# Function for ROT13 (special case of Caesar with key=13)
def rot13():
    text = text_input.get("1.0", "end-1c")
    result = encrypt(text, 13)  # ROT13 is just Caesar with key 13
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)
    status_bar.config(text="Applied ROT13 encryption/decryption")

# Function for Atbash cipher (reverse alphabet)
def atbash_cipher(text):
    result = ""
    for ch in text:
        if ch.islower():
            # Map 'a' to 'z', 'b' to 'y', etc.
            result += chr(219 - ord(ch))  # 219 = ord('a') + ord('z')
        elif ch.isupper():
            # Map 'A' to 'Z', 'B' to 'Y', etc.
            result += chr(155 - ord(ch))  # 155 = ord('A') + ord('Z')
        else:
            result += ch
    return result

def apply_atbash():
    text = text_input.get("1.0", "end-1c")
    result = atbash_cipher(text)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)
    status_bar.config(text="Applied Atbash cipher")

def show_frequency_chart():
    text = text_input.get("1.0", "end-1c")
    if not text.strip():
        status_bar.config(text="Error: No text to analyze")
        return
        
    filtered = [ch.lower() for ch in text if ch.isalpha()]
    if not filtered:
        status_bar.config(text="Error: No letters to analyze")
        return
        
    # Count letter frequencies
    freq = Counter(filtered)
    
    # Create new window for the chart
    chart_window = tk.Toplevel(root)
    chart_window.title("Letter Frequency Analysis")
    chart_window.geometry("800x600")
    chart_window.configure(bg="#222")
    
    # Create matplotlib figure
    fig, ax = plt.subplots(figsize=(10, 6))
    letters = sorted(freq.keys())
    counts = [freq[letter] for letter in letters]
    
    # Create the bar chart
    bars = ax.bar(letters, counts, color='skyblue')
    
    # Add labels and title
    ax.set_xlabel('Letters')
    ax.set_ylabel('Frequency')
    ax.set_title('Letter Frequency Distribution')
    
    # Set dark background
    fig.patch.set_facecolor('#222')
    ax.set_facecolor('#333')
    ax.tick_params(colors='white')
    ax.xaxis.label.set_color('white')
    ax.yaxis.label.set_color('white')
    ax.title.set_color('white')
    
    canvas = FigureCanvasTkAgg(fig, master=chart_window)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    status_bar.config(text="Frequency analysis chart generated")

# GUI Functions
def on_encrypt():
    plaintext = text_input.get("1.0", "end-1c")
    try:
        key = int(entry_key.get())
        if not (0 <= key <= 25):
            raise ValueError("Key must be between 0 and 25")
    except ValueError as e:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"Error: {str(e)}")
        return
    
    result = encrypt(plaintext, key)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

def on_decrypt():
    ciphertext = text_input.get("1.0", "end-1c")
    try:
        key = int(entry_key.get())
        if not (0 <= key <= 25):
            raise ValueError("Key must be between 0 and 25")
    except ValueError as e:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"Error: {str(e)}")
        return
    
    result = decrypt(ciphertext, key)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

def on_brute_force():
    ciphertext = text_input.get("1.0", "end-1c")
    results = brute_force(ciphertext)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, results)

def on_frequency():
    text = text_input.get("1.0", "end-1c")
    results = frequency_analysis(text)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, results)

# --- Color and Font Palette ---
BG_COLOR = "#181A1B"
FG_COLOR = "#E6E6E6"
ACCENT = "#00B8D9"
ENTRY_BG = "#232526"
ENTRY_FG = "#E6E6E6"
BTN_BG = ACCENT
BTN_FG = BG_COLOR
RESULT_FG = ACCENT
FONT = ("Consolas", 12)
TITLE_FONT = ("Consolas", 18, "bold")

# Create the GUI
root = tk.Tk()
root.title("Caesar Cipher Tool")
root.geometry("800x600")
root.configure(bg=BG_COLOR)

main_frame = tk.Frame(root, bg=BG_COLOR, padx=20, pady=20)
main_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(main_frame, text="Caesar Cipher Tool", font=TITLE_FONT, 
         bg=BG_COLOR, fg=ACCENT).pack(pady=(0, 15))

tk.Label(main_frame, text="Input Text:", font=FONT, bg=BG_COLOR, fg=FG_COLOR).pack(anchor="w")
text_input = scrolledtext.ScrolledText(main_frame, height=5, font=FONT, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ACCENT, borderwidth=0)
text_input.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

key_frame = tk.Frame(main_frame, bg=BG_COLOR)
key_frame.pack(fill=tk.X, pady=(0, 10))
tk.Label(key_frame, text="Key (0-25):", font=FONT, bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT)
entry_key = tk.Entry(key_frame, font=FONT, width=5, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ACCENT, borderwidth=0, relief="flat")
entry_key.pack(side=tk.LEFT, padx=(5, 0))

# --- Buttons ---
btn_style = dict(font=FONT, bg=BTN_BG, fg=BTN_FG, activebackground=ACCENT, activeforeground=BTN_FG, padx=10, pady=4, bd=0, relief="flat", cursor="hand2")

crypto_frame = tk.Frame(main_frame, bg=BG_COLOR)
crypto_frame.pack(fill=tk.X, pady=(0, 5))
tk.Button(crypto_frame, text="Encrypt", command=on_encrypt, **btn_style).pack(side=tk.LEFT, padx=(0, 5))
tk.Button(crypto_frame, text="Decrypt", command=on_decrypt, **btn_style).pack(side=tk.LEFT, padx=(0, 5))

attack_frame = tk.Frame(main_frame, bg=BG_COLOR)
attack_frame.pack(fill=tk.X, pady=(0, 5))
tk.Button(attack_frame, text="Brute Force", command=on_brute_force, **btn_style).pack(side=tk.LEFT, padx=(0, 5))
tk.Button(attack_frame, text="Detect Key", command=detect_key, **btn_style).pack(side=tk.LEFT, padx=(0, 5))

stats_frame = tk.Frame(main_frame, bg=BG_COLOR)
stats_frame.pack(fill=tk.X, pady=(0, 5))
tk.Button(stats_frame, text="Frequency Analysis", command=on_frequency, **btn_style).pack(side=tk.LEFT, padx=(0, 5))
tk.Button(stats_frame, text="Frequency Chart", command=show_frequency_chart, **btn_style).pack(side=tk.LEFT, padx=(0, 5))

cipher_frame = tk.Frame(main_frame, bg=BG_COLOR)
cipher_frame.pack(fill=tk.X, pady=(0, 10))
tk.Label(cipher_frame, text="Additional Ciphers:", font=FONT, bg=BG_COLOR, fg=FG_COLOR).pack(side=tk.LEFT, padx=(0, 10))
tk.Button(cipher_frame, text="ROT13", command=rot13, **btn_style).pack(side=tk.LEFT, padx=(0, 5))
tk.Button(cipher_frame, text="Atbash", command=apply_atbash, **btn_style).pack(side=tk.LEFT)

tk.Label(main_frame, text="Results:", font=FONT, bg=BG_COLOR, fg=FG_COLOR).pack(anchor="w", pady=(10, 0))
result_text = scrolledtext.ScrolledText(main_frame, height=10, font=FONT, bg="#111", fg=RESULT_FG, insertbackground=ACCENT, borderwidth=0)
result_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#232526", fg=FG_COLOR, font=FONT)
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

root.mainloop()