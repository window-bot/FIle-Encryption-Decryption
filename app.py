import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

class FileCryptGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Crypt")
        self.root.geometry("600x400")
        
        # Variables
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.key_file = tk.StringVar()
        self.status = tk.StringVar()
        self.status.set("Ready")
        
        # Colors and fonts
        self.bg_color = "#f0f0f0"
        self.button_color = "#e1e1e1"
        self.font = ('Arial', 10)
        
        self.create_widgets()
    
    def create_widgets(self):
        # Configure main window
        self.root.configure(bg=self.bg_color)
        
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        
        # Title
        title = tk.Label(main_frame, 
                        text="File Encryption/Decryption Tool",
                        font=('Arial', 14, 'bold'),
                        bg=self.bg_color)
        title.pack(pady=10)
        
        # Input File Selection
        input_frame = tk.Frame(main_frame, bg=self.bg_color)
        input_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(input_frame, 
                text="Input File:", 
                bg=self.bg_color,
                font=self.font).pack(side=tk.LEFT)
        
        tk.Entry(input_frame, 
                textvariable=self.input_file, 
                width=50,
                font=self.font).pack(side=tk.LEFT, padx=5)
        
        tk.Button(input_frame, 
                 text="Browse", 
                 command=self.browse_input,
                 bg=self.button_color,
                 font=self.font).pack(side=tk.LEFT)
        
        # Output File Selection
        output_frame = tk.Frame(main_frame, bg=self.bg_color)
        output_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(output_frame, 
                text="Output File:", 
                bg=self.bg_color,
                font=self.font).pack(side=tk.LEFT)
        
        tk.Entry(output_frame, 
                textvariable=self.output_file, 
                width=50,
                font=self.font).pack(side=tk.LEFT, padx=5)
        
        tk.Button(output_frame, 
                 text="Browse", 
                 command=self.browse_output,
                 bg=self.button_color,
                 font=self.font).pack(side=tk.LEFT)
        
        # Key File Selection
        key_frame = tk.Frame(main_frame, bg=self.bg_color)
        key_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(key_frame, 
                text="Key File:", 
                bg=self.bg_color,
                font=self.font).pack(side=tk.LEFT)
        
        tk.Entry(key_frame, 
                textvariable=self.key_file, 
                width=50,
                font=self.font).pack(side=tk.LEFT, padx=5)
        
        tk.Button(key_frame, 
                 text="Browse", 
                 command=self.browse_key,
                 bg=self.button_color,
                 font=self.font).pack(side=tk.LEFT)
        
        # Operation Buttons
        button_frame = tk.Frame(main_frame, bg=self.bg_color)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, 
                 text="Generate New Key", 
                 command=self.generate_key,
                 bg=self.button_color,
                 font=self.font).pack(side=tk.LEFT, padx=10)
        
        tk.Button(button_frame, 
                 text="Encrypt File", 
                 command=self.encrypt_file,
                 bg="#c9e4ca",
                 font=self.font).pack(side=tk.LEFT, padx=10)
        
        tk.Button(button_frame, 
                 text="Decrypt File", 
                 command=self.decrypt_file,
                 bg="#f7c9c9",
                 font=self.font).pack(side=tk.LEFT, padx=10)
        
        # Status Bar
        status_frame = tk.Frame(self.root, bg=self.bg_color, bd=1, relief=tk.SUNKEN)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        tk.Label(status_frame, 
                textvariable=self.status,
                bg=self.bg_color,
                font=self.font).pack(side=tk.LEFT)
    
    def browse_input(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.input_file.set(filename)
            # Set default output filename
            if not self.output_file.get():
                if self.key_file.get():
                    base, ext = os.path.splitext(filename)
                    self.output_file.set(f"{base}.enc")
    
    def browse_output(self):
        filename = filedialog.asksaveasfilename()
        if filename:
            self.output_file.set(filename)
    
    def browse_key(self):
        filename = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if filename:
            self.key_file.set(filename)
    
    def generate_key(self):
        key = Fernet.generate_key()
        key_file = filedialog.asksaveasfilename(defaultextension=".key", 
                                               filetypes=[("Key files", "*.key")])
        if key_file:
            try:
                with open(key_file, 'wb') as f:
                    f.write(key)
                self.key_file.set(key_file)
                self.status.set(f"New key generated and saved to {key_file}")
                messagebox.showinfo("Success", "New encryption key generated successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {str(e)}")
    
    def encrypt_file(self):
        if not self.validate_inputs(need_key=False):
            return
        
        input_file = self.input_file.get()
        output_file = self.output_file.get() or f"{input_file}.enc"
        key_file = self.key_file.get() or f"{os.path.splitext(input_file)[0]}.key"
        
        # Generate key if none exists
        if not os.path.exists(key_file):
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            self.key_file.set(key_file)
        else:
            with open(key_file, 'rb') as f:
                key = f.read()
        
        try:
            with open(input_file, 'rb') as f:
                original_data = f.read()
            
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(original_data)
            
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            
            self.status.set(f"File encrypted successfully! Saved to {output_file}")
            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status.set("Encryption failed")
    
    def decrypt_file(self):
        if not self.validate_inputs(need_key=True):
            return
        
        input_file = self.input_file.get()
        output_file = self.output_file.get()
        
        if not output_file:
            if input_file.endswith('.enc'):
                output_file = input_file[:-4]
            else:
                output_file = f"{input_file}.dec"
            self.output_file.set(output_file)
        
        try:
            with open(self.key_file.get(), 'rb') as f:
                key = f.read()
            
            fernet = Fernet(key)
            
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            self.status.set(f"File decrypted successfully! Saved to {output_file}")
            messagebox.showinfo("Success", "File decrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status.set("Decryption failed - invalid key or corrupted file")
    
    def validate_inputs(self, need_key=True):
        if not self.input_file.get():
            messagebox.showerror("Error", "Please select an input file")
            return False
        
        if need_key and not self.key_file.get():
            messagebox.showerror("Error", "Please select a key file for decryption")
            return False
        
        return True

if __name__ == "__main__":
    root = tk.Tk()
    app = FileCryptGUI(root)
    root.mainloop()
