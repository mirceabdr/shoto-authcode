import hashlib
import os

def checksum(password: str) -> str:
    """
    Generează hash-ul SHOTO cu salt fix.

    Pași:
    1. Se verifică dacă parola nu este goală.
    2. Se calculează MD5 al parolei, cu litere mari.
    3. Se concatenează acest hash cu un salt fix.
    4. Se calculează MD5 final, tot cu litere mari.

    :param password: Parola introdusă de utilizator
    :return: Hash-ul final în format hex, litere mari
    """
    if not password.strip():
        raise ValueError("Parola nu poate fi goală")  # Validare input

    salt = b'LD|SD'  # Salt fix în bytes
    md5_hash = hashlib.md5(password.encode('utf-8')).hexdigest().upper()  # MD5 initial, uppercase
    final_hash = hashlib.md5(md5_hash.encode('utf-8') + salt).hexdigest().upper()  # MD5 final cu salt
    return final_hash

def write_pwd_xml(hash_value: str, filename: str = "pwd.xml"):
    """
    Scrie sau rescrie fișierul XML cu hash-ul generat în toate câmpurile de parolă.

    :param hash_value: Hash-ul care va fi scris în fișier
    :param filename: Numele fișierului XML (implicit "pwd.xml")
    """
    xml_content = f"""<?xml version='1.0' encoding='utf-8'?>
<PASSWORD>
  <login_pwd>{hash_value}</login_pwd>
  <parameter_pwd1>{hash_value}</parameter_pwd1>
  <parameter_pwd2>{hash_value}</parameter_pwd2>
  <config_pwd>{hash_value}</config_pwd>
  <system_pwd>{hash_value}</system_pwd>
  <system1_pwd>{hash_value}</system1_pwd>
  <theft_pwd>{hash_value}</theft_pwd>
  <general_pwd>{hash_value}</general_pwd>
  <gyro_pwd>{hash_value}</gyro_pwd>
  <comm_pwd>{hash_value}</comm_pwd>
</PASSWORD>
"""
    # Scrie conținutul în fișier, suprascriind dacă există
    with open(filename, "w", encoding="utf-8") as f:
        f.write(xml_content)

    print(f"Fișierul '{filename}' a fost generat/rescris cu succes.")

if __name__ == "__main__":
    try:
        # Solicită parola de la utilizator (input vizibil)
        pwd = input("Introdu noua parolă: ")
        # Generează hash-ul folosind funcția checksum
        hash_val = checksum(pwd)
        # Scrie hash-ul în fișierul pwd.xml
        write_pwd_xml(hash_val)
    except ValueError as e:
        print("Eroare:", e)
