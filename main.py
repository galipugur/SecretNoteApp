from tkinter import *
from tkinter import messagebox
import base64

window = Tk()
window.title("Secret Notes")
window.config(padx=20, pady=10)

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def msg():
    messagebox.showinfo("Imperfect Data", "Please Don't Leave Blank Spaces!")

def saved():
    secret_note_title = title_input.get()
    secret_note = secret_input.get(1.0, END)
    user_password = password_input.get()

    if secret_note == "" or secret_note_title == "" or user_password == "":
        msg()
    else:
        #encryption
        encrypt_note = encode(user_password, secret_note)
        try:
            with open("new_note.txt", "a") as text_file:
                text_file.write(f"{secret_note_title}\n{encrypt_note}\n")
        except FileNotFoundError:
            with open("new_note.txt", "w") as text_file:
                text_file.write(f"{secret_note_title}\n{encrypt_note}\n")
        finally:
            title_input.delete(0, END)
            secret_input.delete("1.0", END)
            password_input.delete(0, END)

def decrypt():
    encrypted_secret = secret_input.get(1.0, END)
    user_password = password_input.get()

    if len(encrypted_secret) == 0 or len(user_password) == 0:
        msg()
    else:
        try:
            decrypted_message = decode(user_password, encrypted_secret)
            secret_input.delete("1.0", END)
            secret_input.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted message!")

#ui

my_image = PhotoImage(file="sec.png")
image_label = Label(image=my_image)
image_label.pack()

title_label = Label(text="Enter Your Note Title")
title_label.pack()

title_input = Entry(width=40)
title_input.pack()

secret_title = Label(text="Enter Your Secret Note")
secret_title.pack()

secret_input = Text(width=40, height=15)
secret_input.pack()

password_title = Label(text="Enter Your Master Key")
password_title.pack()

password_input = Entry(width=40)
password_input.pack()

save_button = Button(text="Save & Encrypt", command=saved)
save_button.pack(pady= 10)

decrypt_button = Button(text="Decrypt",command=decrypt)
decrypt_button.pack()

window.mainloop()
