
import tkinter as tk
from tkinter import filedialog, messagebox
import base64
import datetime

class FileEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mã hóa & Giải mã Tệp (Mô phỏng DES)")
        self.encrypted_data = None
        self.decrypted_data = None

        # Main frame
        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill="both", expand=True)

        # Date label
        date_label = tk.Label(main_frame, text="Ngày hiện tại: 14 tháng 5, 2025 - 01:47 PM +07")
        date_label.pack(anchor="w")

        # Encryption section
        encrypt_frame = tk.LabelFrame(main_frame, text="Mã hóa Tệp", padx=10, pady=10)
        encrypt_frame.pack(fill="x", pady=10)

        tk.Label(encrypt_frame, text="Mã khóa:").grid(row=0, column=0, sticky="w")
        self.key_encrypt = tk.Entry(encrypt_frame)
        self.key_encrypt.grid(row=0, column=1, padx=5, pady=5)
        self.key_encrypt.insert(0, "Nhập mã khóa để mã hóa")

        self.file_encrypt_btn = tk.Button(encrypt_frame, text="Chọn tệp", command=self.browse_encrypt_file)
        self.file_encrypt_btn.grid(row=1, column=0, padx=5, pady=5)
        self.encrypt_btn = tk.Button(encrypt_frame, text="Mã hóa", command=self.encrypt_file)
        self.encrypt_btn.grid(row=1, column=1, padx=5, pady=5)
        self.download_encrypt_btn = tk.Button(encrypt_frame, text="Tải xuống tệp mã hóa", command=self.save_encrypted_file, state="disabled")
        self.download_encrypt_btn.grid(row=1, column=2, padx=5, pady=5)

        self.encrypt_result = tk.Text(encrypt_frame, height=3, width=50)
        self.encrypt_result.grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        self.encrypt_result.insert(tk.END, "Dữ liệu mã hóa sẽ xuất hiện tại đây...")
        self.encrypt_result.config(state="disabled")

        # Decryption section
        decrypt_frame = tk.LabelFrame(main_frame, text="Giải mã Tệp", padx=10, pady=10)
        decrypt_frame.pack(fill="x", pady=10)

        tk.Label(decrypt_frame, text="Mã khóa:").grid(row=0, column=0, sticky="w")
        self.key_decrypt = tk.Entry(decrypt_frame)
        self.key_decrypt.grid(row=0, column=1, padx=5, pady=5)
        self.key_decrypt.insert(0, "Nhập mã khóa để giải mã")

        self.file_decrypt_btn = tk.Button(decrypt_frame, text="Chọn tệp", command=self.browse_decrypt_file)
        self.file_decrypt_btn.grid(row=1, column=0, padx=5, pady=5)
        self.decrypt_btn = tk.Button(decrypt_frame, text="Giải mã", command=self.decrypt_file)
        self.decrypt_btn.grid(row=1, column=1, padx=5, pady=5)
        self.download_decrypt_btn = tk.Button(decrypt_frame, text="Tải xuống tệp giải mã", command=self.save_decrypted_file, state="disabled")
        self.download_decrypt_btn.grid(row=1, column=2, padx=5, pady=5)

        self.decrypt_result = tk.Text(decrypt_frame, height=3, width=50)
        self.decrypt_result.grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        self.decrypt_result.insert(tk.END, "Dữ liệu giải mã sẽ xuất hiện tại đây...")
        self.decrypt_result.config(state="disabled")

        self.encrypt_file_path = None
        self.decrypt_file_path = None

    def simple_des(self, text, key):
        if not key:
            return text
        result = ""
        for i in range(len(text)):
            result += chr(ord(text[i]) ^ ord(key[i % len(key)]))
        return result

    def browse_encrypt_file(self):
        self.encrypt_file_path = filedialog.askopenfilename()
        if self.encrypt_file_path:
            self.encrypt_result.config(state="normal")
            self.encrypt_result.delete(1.0, tk.END)
            self.encrypt_result.insert(tk.END, f"Đã chọn: {self.encrypt_file_path.split('/')[-1]}")
            self.encrypt_result.config(state="disabled")

    def browse_decrypt_file(self):
        self.decrypt_file_path = filedialog.askopenfilename()
        if self.decrypt_file_path:
            self.decrypt_result.config(state="normal")
            self.decrypt_result.delete(1.0, tk.END)
            self.decrypt_result.insert(tk.END, f"Đã chọn: {self.decrypt_file_path.split('/')[-1]}")
            self.decrypt_result.config(state="disabled")

    def encrypt_file(self):
        key = self.key_encrypt.get()
        if key == "Nhập mã khóa để mã hóa" or not key:
            messagebox.showerror("Lỗi", "Vui lòng nhập mã khóa!")
            return
        if not self.encrypt_file_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn một tệp!")
            return

        try:
            with open(self.encrypt_file_path, "r", encoding="utf-8") as f:
                text = f.read()
            self.encrypted_data = self.simple_des(text, key)
            base64_data = base64.b64encode(self.encrypted_data.encode()).decode()
            self.encrypt_result.config(state="normal")
            self.encrypt_result.delete(1.0, tk.END)
            self.encrypt_result.insert(tk.END, f"Dữ liệu mã hóa (Base64): {base64_data}")
            self.encrypt_result.config(state="disabled")
            self.download_encrypt_btn.config(state="normal")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi mã hóa: {str(e)}")

    def decrypt_file(self):
        key = self.key_decrypt.get()
        if key == "Nhập mã khóa để giải mã" or not key:
            messagebox.showerror("Lỗi", "Vui lòng nhập mã khóa!")
            return
        if not self.decrypt_file_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn một tệp!")
            return

        try:
            with open(self.decrypt_file_path, "r", encoding="utf-8") as f:
                base64_data = f.read()
            text = base64.b64decode(base64_data).decode()
            self.decrypted_data = self.simple_des(text, key)
            self.decrypt_result.config(state="normal")
            self.decrypt_result.delete(1.0, tk.END)
            self.decrypt_result.insert(tk.END, f"Dữ liệu giải mã: {self.decrypted_data}")
            self.decrypt_result.config(state="disabled")
            self.download_decrypt_btn.config(state="normal")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi giải mã: Mã khóa hoặc dữ liệu không hợp lệ! {str(e)}")

    def save_encrypted_file(self):
        if not self.encrypted_data:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.encrypted_data)
            messagebox.showinfo("Thành công", "Tệp mã hóa đã được lưu!")

    def save_decrypted_file(self):
        if not self.decrypted_data:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.decrypted_data)
            messagebox.showinfo("Thành công", "Tệp giải mã đã được lưu!")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptionApp(root)
    root.mainloop()
