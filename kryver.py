import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from datetime import datetime

# Function to open the encryption type selection window
def open_encrypt_algorithm_selection():
    encrypt_algorithm_window = tk.Toplevel(root)
    encrypt_algorithm_window.title("Select Encryption Algorithm")
    encrypt_algorithm_window.geometry("300x200")
    
    label = tk.Label(encrypt_algorithm_window, text="Select encryption algorithm:")
    label.pack(pady=20)
    
    # Buttons to select different algorithms
    rsa_button = tk.Button(encrypt_algorithm_window, text="RSA Encryption", command=lambda: open_rsa_engine_selection_window(encrypt_algorithm_window))
    rsa_button.pack(pady=10)

# Function to open the RSA encryption engine selection window
def open_rsa_engine_selection_window(encrypt_algorithm_window):
    encrypt_algorithm_window.destroy()  # Close the algorithm selection window
    
    rsa_engine_window = tk.Toplevel(root)
    rsa_engine_window.title("Select Encryption Engine")
    rsa_engine_window.geometry("300x200")
    
    label = tk.Label(rsa_engine_window, text="Select encryption engine:")
    label.pack(pady=20)
    
    # Buttons to select different engines
    pycryptodome_button = tk.Button(rsa_engine_window, text="PyCryptodome RSA", command=lambda: open_rsa_encryption_window(rsa_engine_window, "pycryptodome"))
    pycryptodome_button.pack(pady=10)

    #kryver_button = tk.Button(rsa_engine_window, text="kryverRSA", command=lambda: messagebox.showwarning("kryverRSA Engine Error", "kryverRSA is not yet supported."))
    #kryver_button.pack(pady=10)

# Function to open the RSA encryption window based on the selected engine
def open_rsa_encryption_window(rsa_engine_window, engine_type):
    rsa_engine_window.destroy()  # Close the engine selection window
    
    rsa_window = tk.Toplevel(root)
    rsa_window.title("RSA Encryption")
    rsa_window.geometry("800x600")
    
    label = tk.Label(rsa_window, text="Enter text to encrypt:")
    label.pack(pady=20)
    
    text_entry = tk.Entry(rsa_window, width=100)
    text_entry.pack(pady=10)
    
    encrypt_button = tk.Button(rsa_window, text="Encrypt", command=lambda: encrypt_text(text_entry.get(), rsa_window, engine_type))
    encrypt_button.pack(pady=10)
    
    # Save keys and encrypted text buttons
    save_keys_button = tk.Button(rsa_window, text="Save Keys", command=lambda: save_keys(rsa_window))
    save_keys_button.pack(pady=10)
    
    save_encrypted_button = tk.Button(rsa_window, text="Save Encrypted Text", command=lambda: save_encrypted_text(rsa_window))
    save_encrypted_button.pack(pady=10)

# Function to encrypt text using the selected RSA engine
def encrypt_text(text, rsa_window, engine_type):
    # Generate RSA keys (private and public)
    bit_depth = 4096  # adjust this variable to change RSA key size
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Generating RSA keys... Bit depth: {bit_depth}")
    key = RSA.generate(bit_depth)
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - RSA keys generated.")
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    # Store the keys in the root window (so they are accessible to other windows)
    #root.private_key = private_key
    #root.public_key = public_key
    
    # Encrypt the text based on the selected engine
    if engine_type == "pycryptodome":
        encrypted_text = encrypt_with_pycryptodome(text, public_key)
    elif engine_type == "kryver":
        messagebox.showwarning("kryverRSA Engine Error", "kryverRSA is not yet supported.")
    
    # Encode the encrypted text to base64 for easier display
    encrypted_text_b64 = base64.b64encode(encrypted_text).decode('utf-8')
    
    # Display the encrypted text
    messagebox.showinfo("Encrypted Text", f"Encrypted Text (Base64):\n{encrypted_text_b64}")
    
    # Store the encrypted text in the window for later use
    rsa_window.encrypted_text_b64 = encrypted_text_b64
    rsa_window.private_key = private_key
    rsa_window.public_key = public_key

# Function to encrypt text using PyCryptodome
def encrypt_with_pycryptodome(text, public_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text

# Function to save the private and public keys to files
def save_keys(rsa_window):
    try:
        # Ask the user for a file path to save the keys
        private_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")], title="Save Private Key")
        if private_key_path:
            with open(private_key_path, "wb") as private_key_file:
                private_key_file.write(rsa_window.private_key)
        
        public_key_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem")], title="Save Public Key")
        if public_key_path:
            with open(public_key_path, "wb") as public_key_file:
                public_key_file.write(rsa_window.public_key)
        
        messagebox.showinfo("Success", "Keys saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save keys: {e}")

# Function to save the encrypted text to a file
def save_encrypted_text(rsa_window):
    try:
        # Ask the user for a file path to save the encrypted text
        encrypted_text_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")], title="Save Encrypted Text")
        if encrypted_text_path:
            with open(encrypted_text_path, "w") as encrypted_text_file:
                encrypted_text_file.write(rsa_window.encrypted_text_b64)
        
        messagebox.showinfo("Success", "Encrypted text saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save encrypted text: {e}")

# Function to open the decryption window
def open_decrypt_window():
    decrypt_window = tk.Toplevel(root)
    decrypt_window.title("RSA Decryption")
    decrypt_window.geometry("400x300")
    
    label = tk.Label(decrypt_window, text="Select a file to load encrypted text:")
    label.pack(pady=20)
    
    load_encrypted_button = tk.Button(decrypt_window, text="Load Encrypted Text", command=lambda: load_encrypted_text(decrypt_window))
    load_encrypted_button.pack(pady=10)
    
    load_keys_button = tk.Button(decrypt_window, text="Load Private Key", command=lambda: load_private_key(decrypt_window))
    load_keys_button.pack(pady=10)
    
    decrypt_button = tk.Button(decrypt_window, text="Decrypt", command=lambda: decrypt_text(decrypt_window))
    decrypt_button.pack(pady=10)

# Function to load encrypted text from a file
def load_encrypted_text(decrypt_window):
    encrypted_text_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")], title="Select Encrypted Text File")
    if encrypted_text_path:
        with open(encrypted_text_path, "r") as file:
            encrypted_b64 = file.read()
        decrypt_window.encrypted_b64 = encrypted_b64
        messagebox.showinfo("Success", "Encrypted text loaded successfully!")

# Function to load private key from a file
def load_private_key(decrypt_window):
    private_key_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")], title="Select Private Key File")
    if private_key_path:
        with open(private_key_path, "rb") as file:
            private_key = file.read()
        root.private_key = private_key
        messagebox.showinfo("Success", "Private key loaded successfully!")

# Function to decrypt text using RSA with PyCryptodome
def decrypt_text(decrypt_window):
    try:
        # Load the encrypted text and private key
        encrypted_b64 = decrypt_window.encrypted_b64
        private_key = RSA.import_key(root.private_key)
        
        # Decode the encrypted text from Base64
        encrypted_text = base64.b64decode(encrypted_b64)
        
        # Decrypt the text using the private key
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_text = cipher.decrypt(encrypted_text).decode('utf-8')
        
        print(f"Decrypted Text: {decrypted_text}")
        
        # Display the decrypted text
        messagebox.showinfo("Decrypted Text", f"Decrypted Text:\n{decrypted_text}")
    except Exception as e:
        print(f"Decryption failed: {e}")
        messagebox.showerror("Error", "Decryption failed. Ensure the input is valid Base64 encrypted text and the correct private key is loaded.")

# Main GUI setup
print("kryver Version: 1.0 TEST")
print("[kryver] Starting main UI process...")

# Initialize the root window
root = tk.Tk()
root.title("kryver - Main")
root.geometry("400x300")
# Load the image: png/gif tested
icon = tk.PhotoImage(file='data/icon.png')
# Set the window icon
root.iconphoto(True, icon)

# Display a label in the main window
label = tk.Label(root, text="kryver 1.0 TEST")
label.pack(pady=20)

# Encrypt button to open the encryption algorithm selection window
encrypt_button = tk.Button(root, text="Encrypt", command=open_encrypt_algorithm_selection)
encrypt_button.pack(pady=10)

# Decrypt button to open the decryption window
decrypt_button = tk.Button(root, text="Decrypt", command=open_decrypt_window)
decrypt_button.pack(pady=10)

# Main loop
print("[kryver] Starting main UI process... Done.")
root.mainloop()
print("[kryver] Main UI process terminated by user.")
