from PIL import Image, ImageTk
import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

def generate_key_stream(key, length):
    """Generate a pseudo-random key stream from the input key"""
    # Create a hash of the key to get a consistent seed
    key_hash = hashlib.md5(str(key).encode()).digest()
    
    # Use the hash bytes to generate a longer key stream
    key_stream = []
    for i in range(length):
        # Combine hash bytes in a pseudo-random way
        byte_val = key_hash[i % len(key_hash)]
        # Add some variation based on position
        byte_val = (byte_val + i) % 256
        key_stream.append(byte_val)
    
    return key_stream

def encrypt_image(input_path, output_path, key):
    img = Image.open(input_path).convert("RGB")
    pixels = img.load()
    
    # Calculate total pixels for key stream generation
    total_pixels = img.width * img.height
    key_stream = generate_key_stream(key, total_pixels * 3)  # 3 for RGB
    
    key_index = 0
    for x in range(img.width):
        for y in range(img.height):
            r, g, b = pixels[x, y]
            
            # XOR each color channel with a different key byte
            encrypted_r = r ^ key_stream[key_index]
            encrypted_g = g ^ key_stream[key_index + 1]
            encrypted_b = b ^ key_stream[key_index + 2]
            
            pixels[x, y] = (encrypted_r, encrypted_g, encrypted_b)
            key_index += 3

    img.save(output_path, format="PNG")
    return img

def decrypt_image(input_path, output_path, key):
    img = Image.open(input_path)
    pixels = img.load()
    
    # Calculate total pixels for key stream generation
    total_pixels = img.width * img.height
    key_stream = generate_key_stream(key, total_pixels * 3)  # 3 for RGB
    
    key_index = 0
    for x in range(img.width):
        for y in range(img.height):
            r, g, b = pixels[x, y]
            
            # XOR each color channel with the same key bytes (XOR is reversible)
            decrypted_r = r ^ key_stream[key_index]
            decrypted_g = g ^ key_stream[key_index + 1]
            decrypted_b = b ^ key_stream[key_index + 2]
            
            pixels[x, y] = (decrypted_r, decrypted_g, decrypted_b)
            key_index += 3

    img.save(output_path, format="PNG")
    return img

# --- Tkinter UI ---
root = tk.Tk()
root.title("Image Encryption Tool")

def select_file():
    file_path = filedialog.askopenfilename(title="Select image",
                                           filetypes=[("Image files", "*.jpg *.png *.jpeg")])
    return file_path

def show_image(img):
    # Resize image for display if it's too large
    display_img = img.copy()
    if display_img.width > 400 or display_img.height > 400:
        display_img.thumbnail((400, 400), Image.Resampling.LANCZOS)
    
    img_tk = ImageTk.PhotoImage(display_img)
    panel.config(image=img_tk)
    panel.image = img_tk

def process_image(mode):
    input_path = select_file()
    if not input_path:
        return

    output_path = filedialog.asksaveasfilename(defaultextension=".png",
                                           title="Save image",
                                           filetypes=[("PNG", "*.png")])

    if not output_path:
        return

    key_str = key_entry.get()
    if not key_str.isdigit():
        messagebox.showerror("Invalid Input", "Please enter a valid integer key.")
        return

    key = int(key_str)

    try:
        if mode == "encrypt":
            img = encrypt_image(input_path, output_path, key)
            messagebox.showinfo("Success", "Image encrypted successfully!")
        else:
            img = decrypt_image(input_path, output_path, key)
            messagebox.showinfo("Success", "Image decrypted successfully!")

        show_image(img)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# --- UI Elements ---
tk.Label(root, text="Encryption Key (Integer):").pack(pady=5)
key_entry = tk.Entry(root, width=20)
key_entry.pack(pady=5)

tk.Button(root, text="Encrypt Image", command=lambda: process_image("encrypt")).pack(pady=5)
tk.Button(root, text="Decrypt Image", command=lambda: process_image("decrypt")).pack(pady=5)

panel = tk.Label(root, text="Processed image will appear here")
panel.pack(pady=10)

root.mainloop()