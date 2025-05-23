import sqlite3


def init_database():
    with sqlite3.connect("password_vault.db") as db:
        cursor = db.cursor()
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS master(
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL);
            """)

    cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault(
            id INTEGER PRIMARY KEY,
            platform TEXT NOT NULL,
            userid TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            iv TEXT NOT NULL);
            """)
    return db, cursor
