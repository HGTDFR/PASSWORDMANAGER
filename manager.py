import secrets
from functools import partial
from tkinter import Button, Canvas, Entry, Frame, Label, Scrollbar, Tk
from tkinter.constants import BOTH, CENTER, END, LEFT, RIGHT, VERTICAL, Y
import sqlite3
import argon2
from generator import PasswordGenerator
from vault import VaultMethods
from database import init_database

SALT_LENGTH = 16
ARGON2_TIME_COST = 16
ARGON2_MEMORY_COST = 102400
ARGON2_PARALLELISM = 10


class PasswordManager:

    def __init__(self):
        self.db, self.cursor = init_database()
        self.window = Tk()
        self.window.update()
        self.window.title("Password Manager")
        self.window.geometry("650x350")
        self.vault_methods = VaultMethods() #  Не передаем master_password

    def welcome_new_user(self):
        self.window.geometry("450x200")

        label1 = Label(self.window, text="Создайте мастер-пароль")
        label1.config(anchor=CENTER)
        label1.pack(pady=10)

        mp_entry_box = Entry(self.window, width=20, show="*", font=("Arial", 12))
        mp_entry_box.pack()
        mp_entry_box.focus()

        label2 = Label(self.window, text="Введите мастер-пароль еще раз")
        label2.config(anchor=CENTER)
        label2.pack(pady=10)

        rmp_entry_box = Entry(self.window, width=20, show="*", font=("Arial", 12))
        rmp_entry_box.pack()

        self.feedback = Label(self.window)
        self.feedback.pack()

        save_btn = Button(self.window, text="Создать пароль",
                          command=partial(self.save_master_password, mp_entry_box, rmp_entry_box))
        save_btn.pack(pady=5)

    def login_user(self):
        for widget in self.window.winfo_children():
            widget.destroy()

        self.window.geometry("450x200")

        label1 = Label(self.window, text="Введите мастер-пароль")
        label1.config(anchor=CENTER)
        label1.pack(pady=10)

        self.password_entry_box = Entry(self.window, width=20, show="*", font=("Arial", 12))
        self.password_entry_box.pack(pady=5)

        self.feedback = Label(self.window)
        self.feedback.pack(pady=5)

        login_btn = Button(self.window, text="Войти", command=partial(
            self.check_master_password, self.password_entry_box))
        login_btn.pack(pady=5)

    def save_master_password(self, eb1, eb2):
        password = eb1.get()
        password2 = eb2.get()
        if password == password2:
            try:
                # Генерируем соль
                salt = secrets.token_hex(SALT_LENGTH).encode('utf-8')  # Генерируем соль в байтах

                # Хешируем пароль с использованием Argon2
                password_hash = self.hash_password(password, salt)

                # Сохраняем хеш и соль в базе данных
                insert_command = """INSERT INTO master(password_hash, salt) VALUES(?, ?)"""
                self.cursor.execute(insert_command, [password_hash, salt.decode('utf-8')]) # Сохраняем соль как строку
                self.db.commit()
                self.login_user()
            except Exception as e:
                print(f"Error saving master password: {e}")
                self.feedback.config(
                    text="Ошибка при сохранении пароля", fg="red")
        else:
            self.feedback.config(text="Мастер-пароли не совпадают", fg="red")

    def check_master_password(self, eb):
        password = eb.get()

        try:
            # Получаем хеш и соль из базы данных
            self.cursor.execute("SELECT password_hash, salt FROM master WHERE id = 1")
            result = self.cursor.fetchone()

            if result:
                password_hash, salt = result
                salt = salt.encode('utf-8') # Преобразуем соль в байты
                # Проверяем пароль с использованием Argon2
                if self.verify_password(password, password_hash, salt):
                    # Успешная аутентификация
                    self.salt = salt #  Сохраняем соль
                    self.master_password = password
                    self.password_vault_screen()
                else:
                    self.password_entry_box.delete(0, END)
                    self.feedback.config(text="Неверный пароль", fg="red")
            else:
                self.feedback.config(
                    text="Пользователь не найден", fg="red")  # not found
        except Exception as e:
            print(f"Error checking master password: {e}")
            self.feedback.config(text="Ошибка проверки пароля", fg="red")

    def hash_password(self, password, salt):
        """Хеширует пароль с использованием Argon2."""
        password_encoded = password.encode('utf-8')
        try:
            ph = argon2.PasswordHasher(
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=32,
                salt_len=SALT_LENGTH
            )
            return ph.hash(password_encoded, salt=salt)
        except argon2.exceptions.HashingError as e:
            print(f"Hashing failed: {e}")
            return None

    def verify_password(self, password, password_hash, salt):
        """Проверяет, соответствует ли пароль хешу, используя Argon2."""
        password_encoded = password.encode('utf-8')
        try:
            ph = argon2.PasswordHasher()
            return ph.verify(password_hash, password_encoded)
        except argon2.exceptions.VerifyMismatchError:
            # Пароль не соответствует хешу
            return False
        except argon2.exceptions.HashingError as e:
            print(f"Verification failed: {e}")
            return False

    def password_vault_screen(self):
        for widget in self.window.winfo_children():
            widget.destroy()

        #self.vault_methods = VaultMethods(self.master_password)  # Передаем мастер-пароль

        self.window.geometry("850x350")
        main_frame = Frame(self.window)
        main_frame.pack(fill=BOTH, expand=1)

        main_canvas = Canvas(main_frame)
        main_canvas.pack(side=LEFT, fill=BOTH, expand=1)

        main_scrollbar = Scrollbar(
            main_frame, orient=VERTICAL, command=main_canvas.yview)
        main_scrollbar.pack(side=RIGHT, fill=Y)

        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        main_canvas.bind('<Configure>', lambda e: main_canvas.configure(
            scrollregion=main_canvas.bbox("all")))

        second_frame = Frame(main_canvas)
        main_canvas.create_window((0, 0), window=second_frame, anchor="nw")

        generate_password_btn = Button(second_frame, text="Генерировать пароль",
                                       command=PasswordGenerator)
        generate_password_btn.grid(row=1, column=2, pady=10)

        add_password_btn = Button(
            second_frame, text="Добавить новый пароль", command=partial(self.vault_methods.add_password, self.master_password, self.salt, self.password_vault_screen))
        add_password_btn.grid(row=1, column=3, pady=10)

        lbl = Label(second_frame, text="Платформа")
        lbl.grid(row=2, column=0, padx=40, pady=10)
        lbl = Label(second_frame, text="Email/Телефон")
        lbl.grid(row=2, column=1, padx=40, pady=10)
        lbl = Label(second_frame, text="Пароль")
        lbl.grid(row=2, column=2, padx=40, pady=10)

        self.cursor.execute("SELECT * FROM vault")

        if self.cursor.fetchall():
            i = 0
            while True:
                self.cursor.execute("SELECT * FROM vault")
                array = self.cursor.fetchall()

                platform_label = Label(second_frame, text=(array[i][1]))
                platform_label.grid(column=0, row=i + 3)

                account_label = Label(second_frame, text=(array[i][2]))
                account_label.grid(column=1, row=i + 3)

                # Decrypt and display password
                encrypted_password = array[i][3]
                decrypted_password = self.vault_methods.decrypt_password(
                    encrypted_password, self.master_password, self.salt)
                password_label = Label(second_frame, text=decrypted_password)
                password_label.grid(column=2, row=i + 3)

                copy_btn = Button(second_frame, text="Копировать пароль",
                                  command=partial(self.copy_text, decrypted_password))
                copy_btn.grid(column=3, row=i + 3, pady=10, padx=10)
                update_btn = Button(second_frame, text="Обновить пароль",
                                    command=partial(self.vault_methods.update_password, array[i][0], self.master_password, self.salt, self.password_vault_screen))
                update_btn.grid(column=4, row=i + 3, pady=10, padx=10)
                remove_btn = Button(second_frame, text="Удалить пароль",
                                    command=partial(self.vault_methods.remove_password, array[i][0], self.password_vault_screen))
                remove_btn.grid(column=5, row=i + 3, pady=10, padx=10)

                i += 1

                self.cursor.execute("SELECT * FROM vault")
                if len(self.cursor.fetchall()) <= i:
                    break

    def copy_text(self, text):
        self.window.clipboard_clear()
        self.window.clipboard_append(text)


if __name__ == '__main__':
    db, cursor = init_database()
    # Удалить столбец iv из таблицы vault при первом запуске
    try:
        cursor.execute("ALTER TABLE vault DROP COLUMN iv")
        db.commit()
        print("Столбец 'iv' успешно удален из таблицы 'vault'.")
    except sqlite3.OperationalError as e:
        if "no such column: iv" in str(e):
            print("Столбец 'iv' не существует в таблице 'vault'.")
        else:
            print(f"Ошибка при удалении столбца 'iv': {e}")

    cursor.execute("SELECT * FROM master")
    manager = PasswordManager()
    if cursor.fetchall():
        manager.login_user()
    else:
        manager.welcome_new_user()
    manager.window.mainloop()
