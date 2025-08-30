import sqlite3
import hashlib
import datetime
import os
import shutil
from utils import log_event

class Database:
    def __init__(self):
        self.db_path = 'users.db'
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT UNIQUE,
                password_hash TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT,
                to_user TEXT,
                subject TEXT,
                body TEXT,
                attachment_path TEXT,
                timestamp TEXT
            )
        ''')
        conn.commit()
        conn.close()
        log_event("База данных инициализирована")

    def register_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            log_event(f"Пользователь зарегистрирован: {username}")
        except sqlite3.IntegrityError:
            conn.close()
            log_event(f"Ошибка регистрации: пользователь {username} уже существует")
            raise ValueError("Пользователь уже существует")
        finally:
            conn.close()

    def validate_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, hashed_password))
        user = cursor.fetchone()
        conn.close()
        return bool(user)

    def send_message(self, from_user, to_user, subject, body, attachment_path):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (to_user,))
        if not cursor.fetchone():
            conn.close()
            log_event(f"Ошибка отправки сообщения: получатель {to_user} не найден")
            raise ValueError("Получатель не найден")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if attachment_path:
            os.makedirs('message_attachments', exist_ok=True)
            base_name = os.path.basename(attachment_path)
            new_attachment_path = os.path.join('message_attachments', f"{from_user}_{timestamp.replace(':', '-')}_{base_name}")
            shutil.copy(attachment_path, new_attachment_path)
        else:
            new_attachment_path = None

        cursor.execute("""
            INSERT INTO messages (from_user, to_user, subject, body, attachment_path, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (from_user, to_user, subject, body, new_attachment_path, timestamp))
        conn.commit()
        conn.close()
        log_event(f"Сообщение отправлено от {from_user} к {to_user}")
        return new_attachment_path

    def get_messages(self, username):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, from_user, subject, body, attachment_path, timestamp FROM messages WHERE to_user = ? ORDER BY timestamp DESC", (username,))
        messages = cursor.fetchall()
        conn.close()
        return messages

    def delete_message(self, message_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT attachment_path FROM messages WHERE id = ?", (message_id,))
        attachment = cursor.fetchone()
        if attachment and attachment[0]:
            try:
                os.remove(attachment[0])
                log_event(f"Вложение удалено: {attachment[0]}")
            except:
                log_event(f"Ошибка удаления вложения: {attachment[0]}")
        cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        conn.commit()
        conn.close()
        log_event(f"Сообщение {message_id} удалено")