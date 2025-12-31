import tkinter as tk
import time
from tkinter import messagebox

import franc_enigma_256 as enigma

ENCODING : str = "utf-8"

class UIManager:
    def __init__(self, root : tk.Tk) -> None:
        self.root = root
        self.ui_setup()

    def ui_setup(self) -> None:
        self.root.title(f"FrancEnigma-{enigma.VERSION.decode(ENCODING)}")
        self.root.geometry("800x640")
        self.root.resizable(False,False)
        self.root.option_add("*Font", ("Noto Sans Mono",14))

        self.key_entry = tk.Entry(self.root)
        self.text_box = tk.Text(self.root)
        self.scrollbar = tk.Scrollbar(self.root,command=self.text_box.yview)

        self.generate_key_button = tk.Button(
            self.root,
            text="生成",
            command=self.generate_key
        )
        self.encryption_button = tk.Button(
            self.root,
            text="加密",
            command=self.access_encryption
        )
        self.decryption_button = tk.Button(
            self.root,
            text="解密",
            command=self.access_decryption
        )

        self.key_entry.place(x=15,y=15,width=715,height=35)
        self.text_box.place(x=15, y=55, width=755, height=510)
        self.scrollbar.place(x=770, y=55, width=15, height=510)
        self.text_box.config(yscrollcommand=self.scrollbar.set)

        self.key_entry.bind("<Control-Key-a>", self.select_all_entry)
        self.key_entry.bind("<Control-Key-A>", self.select_all_entry)
        self.text_box.bind("<Control-Key-a>", self.select_all_text)
        self.text_box.bind("<Control-Key-A>", self.select_all_text)

        self.generate_key_button.place(x=735,y=15,width=50,height=35)
        self.encryption_button.place(x=15, y=575,width=375, height=50)
        self.decryption_button.place(x=410, y=575,width=375, height=50)

        self.processing_ui(False)

    def processing_ui(self, is_processing : bool) -> None:
        if is_processing == True:
            self.root.config(cursor="watch")
            self.text_box.config(cursor="watch",state = "disabled")
            self.key_entry.config(cursor="watch",state = "disabled")
            self.encryption_button.config(state = "disabled")
            self.decryption_button.config(state = "disabled")
            self.generate_key_button.config(state = "disabled")
        else:
            self.root.config(cursor="arrow")
            self.text_box.config(cursor="xterm",state = "normal")
            self.key_entry.config(cursor="xterm",state = "normal")
            self.encryption_button.config(state = "normal")
            self.decryption_button.config(state = "normal")
            self.generate_key_button.config(state = "normal")
        self.root.update()

    def access_encryption(self) -> None:
        user_key : bytes = ''.join(self.key_entry.get().split()).encode(ENCODING)
        user_text : bytes = self.text_box.get("1.0", "end-1c").encode(ENCODING)

        start_time : float = time.time()
        self.processing_ui(True)
        cryption_program = enigma.Cryption(user_text, user_key)
        cryption_result : str = cryption_program.encryption().hex()
        processed_result : str = '\n'.join([cryption_result[i:i + 64] for i in range(0, len(cryption_result), 64)])
        self.processing_ui(False)
        end_time : float = time.time()

        self.set_text_box(processed_result)
        messagebox.showinfo("加密完成",f"总共花费{int((end_time - start_time)*1000)/1000}秒")

    def access_decryption(self) -> None:
        user_key : bytes = ''.join(self.key_entry.get().split()).encode(ENCODING)
        try:
            crypted_text : bytes = bytes.fromhex(''.join((self.text_box.get("1.0", "end-1c").lower()).split()))
        except:
            messagebox.showerror("解密失败","密文不正确。")
            return
        
        start_time : float = time.time()
        self.processing_ui(True)
        cryption_program = enigma.Cryption(crypted_text, user_key)
        cryption_result : tuple[bytes, bool] = cryption_program.decryption()
        self.processing_ui(False)
        end_time : float = time.time()

        if cryption_result[1] == True:
            self.set_text_box(cryption_result[0].decode(ENCODING))
            messagebox.showinfo("解密完成",f"总共花费{int((end_time - start_time)*1000)/1000}秒")
        else:
            messagebox.showerror("解密失败","密钥、密文不正确。")

    def generate_key(self) -> None:
        new_key : str = enigma.get_random_bytes().hex()
        self.key_entry.delete(0,tk.END)
        self.key_entry.insert(0,new_key)

    def set_text_box(self, new_text : str) -> None:
        self.text_box.delete("1.0", "end-1c")
        self.text_box.insert("1.0", new_text)

    def select_all_text(self,_) -> str:
        self.text_box.tag_add(tk.SEL, "1.0", tk.END)
        self.text_box.mark_set(tk.INSERT, "1.0")
        self.text_box.see(tk.INSERT)
        return "break"
    
    def select_all_entry(self,_) -> str:
        self.key_entry.select_range(0, tk.END)
        return "break"

def main() -> None:
    root = tk.Tk()
    app = UIManager(root)
    _ = app
    root.mainloop()

if __name__ == "__main__":
    main()