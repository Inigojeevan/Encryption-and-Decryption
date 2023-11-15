from tkinter import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

class EDCrypt:
    def __init__(self, root):
        self.root = root
        self.root.title("EDCrypt")
        self.root.geometry("850x500")
        self.root.configure(bg="#990000")
        self.root.resizable(False, False)

        self.text1 = Text(root, font=("Dialog", 14), fg="black", height=5, width=40, bd=2, relief="solid")
        self.text1.place(x=80, y=80)

        self.text2 = Text(root, font=("Dialog", 14), fg="black", height=5, width=40, bd=2, relief="solid")
        self.text2.place(x=80, y=322)

        self.text3 = Text(root, font=("Dialog", 14), fg="black", height=5, width=40, bd=2, relief="solid")
        self.text3.place(x=470, y=80)

        self.text4 = Text(root, font=("Dialog", 14), fg="black", height=5, width=40, bd=2, relief="solid")
        self.text4.place(x=470, y=320)

        self.msg1 = Entry(root, font=("Dialog", 14), fg="black", bg="white", justify='center', show='*')
        self.msg1.place(x=200, y=220, width=180, height=30)

        self.msg2 = Entry(root, font=("Dialog", 14), fg="black", bg="white", justify='center', show='*')
        self.msg2.place(x=595, y=220, width=190, height=30)

        self.encrypt_btn = Button(root, text="Encrypt", font=("Dialog", 14, "bold"), fg="white", bg="#003333",
                                  command=self.encrypt_action)
        self.encrypt_btn.place(x=80, y=275, width=90, height=30)

        self.decrypt_btn = Button(root, text="Decrypt", font=("Dialog", 14, "bold"), fg="white", bg="#003333",
                                  command=self.decrypt_action)
        self.decrypt_btn.place(x=470, y=275, width=90, height=30)

        self.copy_encrypt_btn = Button(root, text="Copy Encryption", font=("Dialog", 12, "bold"), fg="white",
                                       bg="#660000", command=self.copy_encrypt_action)
        self.copy_encrypt_btn.place(x=240, y=275, width=140, height=30)

        self.copy_decrypt_btn = Button(root, text="Copy Decryption", font=("Dialog", 12, "bold"), fg="white",
                                       bg="#660000", command=self.copy_decrypt_action)
        self.copy_decrypt_btn.place(x=633, y=275, width=150, height=30)

        self.message1 = Label(root, text="", font=("Dialog", 12), fg="#CC0000", bg="#990000")
        self.message1.place(x=80, y=450, width=300, height=20)

        self.message2 = Label(root, text="", font=("Dialog", 12), fg="#CC0000", bg="#990000")
        self.message2.place(x=470, y=450, width=320, height=20)

    def set_key(self, my_key):
        secret_key_str = "mysecretkey12345"
        sha = hashlib.sha1()
        sha.update(secret_key_str.encode("utf-8"))
        hashed_key = sha.digest()
        self.key = hashed_key[:16]
        self.secret_key = AES.new(self.key, AES.MODE_ECB)

    def encrypt_action(self):
        try:
            str_to_encrypt = self.text1.get("1.0", END).strip()
            secret = self.msg1.get()
            self.set_key(secret)
            encrypted_text = self.secret_key.encrypt(pad(str_to_encrypt.encode("utf-8"), AES.block_size))
            self.text2.delete("1.0", END)
            self.text2.insert(END, base64.b64encode(encrypted_text).decode("utf-8"))
        except Exception as e:
            self.text2.delete("1.0", END)
            self.text2.insert(END, "Please fill up the right secret key")

    def decrypt_action(self):
        try:
            secret = self.msg2.get()
            str_to_decrypt = self.text3.get("1.0", END).strip()
            self.set_key(secret)
            decrypted_text = unpad(self.secret_key.decrypt(base64.b64decode(str_to_decrypt)), AES.block_size)
            self.text4.delete("1.0", END)
            self.text4.insert(END, decrypted_text.decode("utf-8"))
        except Exception as e:
            self.text4.delete("1.0", END)
            self.text4.insert(END, "Please fill up the right secret key")

    def copy_encrypt_action(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.text2.get("1.0", END).strip())
        self.root.update()
        self.message1.config(text="Your encryption result is copied!")
        self.message2.config(text="")

    def copy_decrypt_action(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.text4.get("1.0", END).strip())
        self.root.update()
        self.message2.config(text="Your decryption result is copied!")
        self.message1.config(text="")


if __name__ == "__main__":
    root = Tk()
    edcrypt_app = EDCrypt(root)
    root.mainloop()
