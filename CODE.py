import pyDes                 		#import library pyDes
import base64                		#import library base64
import sys
from tkinter import *        		#import library tkinter for GUI
from tkinter import filedialog
import io
from pyDes import *
  
root = Tk()
root.geometry("400x400")
root.title("Image Encryption & Decryption")
root.configure(bg='#000000')
first=StringVar()
second= StringVar()
enc = "encrypted.txt"
out = "output.jpg"

# Function to get the encryption keys
def get_key_en():
	key1=first.get()
	key2=second.get()
	encrypt(key1,key2,img,enc)			#Calling an encrypt function

# Function to get the decryption keys
def get_key_de():
	key1=first.get()
	key2=second.get()
	decrypt(key1, key2,enc, out)		#Calling an decrypt function

# Function to Encrypt an Image with Triple DES
def encrypt(key1,key2, path, output = 'Encrypted.txt'):
  with open(path, 'rb') as file1:
    plaintext = file1.read()
    cipher_encrypt = triple_des(key1, CBC, key2, pad=None, padmode= PAD_PKCS5)
    ciphertext = cipher_encrypt.encrypt(plaintext)
    with open(output, 'wb') as file2:
      file2.write(ciphertext)
  print("Encryption Complete.")
  root.destroy()
  
# Function to Decrypt an Image with Triple DES
def decrypt(key1,key2, path = 'Encrypted.txt', output = 'Decrypted.jpg'):
  with open(path, 'rb') as file1:
    ciphertext = file1.read()
    cipher_decrypt = triple_des(key1, CBC, key2, pad=None, padmode= PAD_PKCS5)
    plaintext = cipher_decrypt.decrypt(ciphertext)
    with open(output, 'wb') as file2:
      file2.write(plaintext)
  print("Decryption Complete.")
  root.destroy()

imgToEncrypt = filedialog.askopenfile(mode='r', filetypes=[('jpg file', '*.jpg'), ('png file', '*.png'),('txt file','*.txt')])	# opening a file dialog
img=imgToEncrypt.name

label3 = Label(root, text="3DES ENCRYPTION", bg='#000000',fg="#00FF00",font=("Arial",25)).place(x=40, y=60)
label3 = Label(root, text="Enter the keys to Encrypt / Decrypt the File",bg='#000000',fg="#32CD32", font=("Arial",15)).place(x=7, y=130)

entry1 = Entry(root, textvariable=first,bg='#C0C0C0', width=30)							#key1
entry1.place(x=95, y=200)
label1 = Label(root, text="Key 1:",bg='#000000',fg="#32CD32").place(x=40, y=200)
label1Result = Label(root)

entry2 = Entry(root, textvariable=second,bg='#C0C0C0', width=30)						#key2
entry2.place(x=95, y=260)
label2 = Label(root, text="Key 2:",bg='#000000',fg="#32CD32").place(x=40, y=260)
label2Result = Label(root)

b = Button(root, text="Encrypt", command=get_key_en)
b.place(x=110, y=330)

b = Button(root, text="Decrypt",command=get_key_de)
b.place(x=240, y=330)

root.mainloop()
