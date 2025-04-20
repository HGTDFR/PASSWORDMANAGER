import base64
from tkinter import simpledialog

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from database import init_database


class VaultMethods:

    def __init__(self):  # Убрали master_password из init
        self.db, self.cursor = init_database()

    def popup_entry(self, heading):
        answer = simpledialog.askstring("Введите детали", heading)
        return answer

    def generate_key(self, master_password, salt):  # Принимаем master_password и salt
        password_provided = master_password.encode()
        password = password_provided
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000,  # Увеличили количество итераций
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt_password(self, password, master_password, salt):  # Принимаем master_password и salt
        key = self.generate_key(master_password, salt)
        message = password.encode()
        f = Fernet(key)
        encrypted = f.encrypt(message)
        return encrypted

    def decrypt_password(self, encrypted_password, master_password, salt):  # Принимаем master_password и salt
        key = self.generate_key(master_password, salt)
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_password)
        return decrypted.decode()

    def add_password(self, master_password, salt, vault_screen):  # Принимаем master_password и salt
        platform = self.popup_entry("Платформа")
        userid = self.popup_entry("Username/Телефон")
        password = self.popup_entry("Пароль")

        encrypted_password = self.encrypt_password(password, master_password, salt)

        insert_cmd = """INSERT INTO vault(platform, userid, encrypted_password) VALUES (?, ?, ?)"""  # Убрали iv
        self.cursor.execute(insert_cmd, (platform, userid, encrypted_password))
        self.db.commit()
        vault_screen()

    def update_password(self, id, master_password, salt, vault_screen):  # Принимаем master_password и salt
        password = self.popup_entry("Введите новый пароль")
        encrypted_password = self.encrypt_password(password, master_password, salt)
        self.cursor.execute(
            "UPDATE vault SET encrypted_password = ? WHERE id = ?", (encrypted_password, id))  # Убрали iv
        self.db.commit()
        vault_screen()

    def remove_password(self, id, vault_screen):
        self.cursor.execute("DELETE FROM vault WHERE id = ?", (id,))
        self.db.commit()
        vault_screen()
