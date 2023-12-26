import tkinter as tk
import sys
class CaeserCipher(tk.Frame):

    def __init__(self, root):
        self.colour1 = '#072b63'
        self.colour2 = '#bfe2ff'
        self.colour3 = '#89b9e1'

        self.letter = 'abcdefghijklmnopqrstuvwxyz'
        self.num_letters = len(self.letter)

        super().__init__(root, bg=self.colour1)
        self.main_frame = self
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.columnconfigure(0, weight=1)
        self.plaintext = tk.StringVar(self.main_frame, value="")
        self.ciphertext = tk.StringVar(self.main_frame, value="")
        self.key = tk.IntVar(self.main_frame)
        self.render_widgets()

    def render_widgets(self):
        self.frame2 = tk.LabelFrame(self.main_frame,height=200,width=200,bg=self.colour1)
        self.frame2.grid(row=1)
        self.title = tk.Label(
            self.main_frame, bg=self.colour1, fg=self.colour2, font=('Arial', 22, 'bold'), text='Caeser Cipher Decoder'
        )
        self.title.grid(column=0, row=0, sticky=tk.EW, pady=35)

        self.plaintext = tk.StringVar(self.frame2, value="")
        self.ciphertext = tk.StringVar(self.frame2, value="")
        self.key = tk.IntVar(self.frame2)
        self.cipher_label = tk.Label(self.frame2, text="Ciphertext:", fg=self.colour2,bg=self.colour1, font=('Arial', 22, 'bold')).grid(row=1, column=0,pady=20)
        self.cipher_entry = tk.Entry(self.frame2,
                                     textvariable=self.ciphertext, width=20, bg=self.colour2, fg=self.colour1,
                                     font=('Arial', 22, 'bold'))
        self.cipher_entry.grid(row=1, column=1,padx=20)
        self.decrypt_button = tk.Button(self.frame2, text="Decrypt",command=lambda: self.decrypt_callback(), fg=self.colour1,bg=self.colour3,font=('Arial', 22, 'bold')).grid(row=1, column=2)
        self.cipher_clear = tk.Button(self.frame2, text="Clear",
                                      command=lambda: self.clear('cipher'), fg=self.colour1,bg=self.colour3,font=('Arial', 22, 'bold')).grid(row=1, column=3)


        # Key controls
        self.key_label = tk.Label(self.frame2, text="Key:", fg=self.colour2,bg=self.colour1,font=('Arial', 22, 'bold')).grid(row=2, column=0)
        self.key_entry = tk.Entry(self.frame2, textvariable=self.key, bg=self.colour2,width=10, font=('Arial', 22, 'bold')).grid(row=2, column=1,
                                                                                           sticky=tk.W, padx=20)
        # Plaintext controls
        self.plain_label = tk.Label(self.frame2, text="Plaintext:", fg=self.colour2,bg=self.colour1, font=('Arial', 22, 'bold')).grid(row=3, column=0)
        self.plain_entry = tk.Entry(self.frame2,
                                    textvariable=self.plaintext, bg=self.colour2,width=20, font=('Arial', 22, 'bold'))
        self.plain_entry.grid(row=3, column=1, padx=20)
        self.plain_clear = tk.Button(self.frame2, text="Clear",
                                     command=lambda: self.clear('plain'), fg=self.colour1,bg=self.colour3,font=('Arial', 22, 'bold')).grid(row=3, column=2)

    def clear(self, str_val):
        if str_val == 'cipher':
            self.cipher_entry.delete(0, 'end')
        elif str_val == 'plain':
            self.plain_entry.delete(0, 'end')

    def get_key(self):
        try:
            key_val = self.key.get()
            return key_val
        except tk.TclError:
            pass

    def decrypt(self,ciphertext, key):
        plaintext = ""
        for char in ciphertext.upper():
            if char.isalpha():
                plaintext += chr((ord(char) - key - 65) % 26 + 65)
            else:
                plaintext += char
        return plaintext

    def decrypt_callback(self):
        key = self.get_key()
        plaintext = self.decrypt(self.cipher_entry.get(),key)
        self.plain_entry.delete(0, tk.END)
        self.plain_entry.insert(0, plaintext)

operating_system = sys.platform
root = tk.Tk()
caeser_cipher_app = CaeserCipher(root)
root.title = 'Caeser Cipher'
root.geometry('800x450')

root.mainloop()
