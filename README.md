# 🔐 Shoto Password Hasher

> Python tool for generating SHOTO password hashes and writing them into an XML configuration file.

![Shoto Password Hasher](https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,100:2c5364&height=200&section=header&text=Shoto%20Password%20Hasher&fontSize=40&fontColor=ffffff)


## 🧠 Overview

This project implements a **SHOTO password hash generator** with a fixed salt.  
It produces a `pwd.xml` file containing the hash in all relevant password fields.

The generator takes:

* Password input

…and produces a valid hashed XML using:

* Fixed-salt MD5 hashing
* Double MD5 hashing pipeline
* Standardized XML output


## ⚙️ Features

* 🔹 Fully offline (no API required)  
* 🔹 Deterministic output  
* 🔹 Fixed-salt MD5 hashing (`LD|SD`)  
* 🔹 CLI-based interactive usage  
* 🔹 Clean and documented code


## 🔬 Algorithm Flow


INPUT (password)
↓
checksum()
↓
MD5 (uppercase) + fixed salt LD|SD
↓
MD5 final (uppercase)
↓
write_pwd_xml() → config/pwd.xml



## 📦 Installation

```bash
git clone https://github.com/USERNAME/ShotoHasher.git
cd ShotoHasher
```

## ▶️ Usage
```bash
python shoto_hasher.py
```

Enter your password when prompted.
The pwd.xml file will be created automatically.

Example
python shoto_hasher.py

Output:
pwd.xml  ← generated automatically


## 🔑 Parameters
Param	Description
password	User input password
pwd.xml will be generated

## 🧪 Technical Details
Hash is generated in 2 steps:
MD5 of password (uppercase)
Concatenated with fixed salt LD|SD → MD5 final (uppercase)
Final hash is written in all password fields of pwd.xml

## ⚠️ Disclaimer
This project is for:

Educational purposes
Research and backup
Understanding SHOTO password hashing

❗ Do not use this tool for unauthorized access to devices or systems.

## 👨‍💻 Author
GitHub: https://github.com/mirceabdr

## ⭐ Support

If you like this project:
⭐ Star the repo
🍴 Fork it
🧠 Contribute and improve
