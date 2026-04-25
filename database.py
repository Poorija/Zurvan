import sqlite3
import hashlib
import os
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

DATABASE_NAME = "zurvan_user_data.db"
# This key should be stored securely and not hardcoded in a real application.
# For this example, we'll derive it from a static password.
# In a real-world scenario, this might come from a hardware security module,
# an environment variable, or a secure vault.
ENCRYPTION_KEY_PASSWORD = b'zurvan-static-encryption-key-!@#$'
SALT = b'zurvan_salt_12345678' # Salt should also be unique and stored securely.

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def _get_encryption_key():
    """Derives a key from the password for encryption."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_KEY_PASSWORD))
    return key

_ENCRYPTION_CIPHER = Fernet(_get_encryption_key())

def encrypt_data(data):
    """Encrypts data. Expects bytes."""
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    return _ENCRYPTION_CIPHER.encrypt(data)

def decrypt_data(token):
    """Decrypts data. Returns bytes."""
    if not isinstance(token, bytes):
        token = token.encode('utf-8')
    try:
        return _ENCRYPTION_CIPHER.decrypt(token)
    except Exception as e:
        logging.error(f"Failed to decrypt data: {e}")
        return b'' # Return empty bytes on failure

def _add_column_if_not_exists(cursor, table_name, column_name, column_type):
    """Utility to add a column to a table if it doesn't already exist."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
        logging.info(f"Added column '{column_name}' to table '{table_name}'.")

def create_tables():
    """Creates the necessary tables in the database if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # User table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Add profile columns if they don't exist, for backward compatibility
    _add_column_if_not_exists(cursor, "users", "full_name", "TEXT")
    _add_column_if_not_exists(cursor, "users", "age", "INTEGER")
    _add_column_if_not_exists(cursor, "users", "job_title", "TEXT")

    # Add brute-force protection columns
    _add_column_if_not_exists(cursor, "users", "failed_login_attempts", "INTEGER DEFAULT 0")
    _add_column_if_not_exists(cursor, "users", "lockout_until", "TIMESTAMP")
    _add_column_if_not_exists(cursor, "users", "lockout_level", "INTEGER DEFAULT 0")

    # Add avatar column
    _add_column_if_not_exists(cursor, "users", "avatar", "BLOB")

    # Add App Lock columns
    _add_column_if_not_exists(cursor, "users", "app_lock_timeout", "INTEGER DEFAULT 15")
    _add_column_if_not_exists(cursor, "users", "app_unlock_method", "TEXT DEFAULT 'password'")
    _add_column_if_not_exists(cursor, "users", "pin_hash", "TEXT")
    _add_column_if_not_exists(cursor, "users", "otp_secret", "TEXT")

    # Security questions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        answer_hash TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)

    # Pre-defined security questions (for reference in the application)
    # This list will be used by the registration UI.
    SECURITY_QUESTIONS_LIST = [
        "What was your first pet's name?",
        "What is your mother's maiden name?",
        "What was the name of your elementary school?",
        "What city were you born in?",
        "What is your favorite book?",
        "What was the model of your first car?",
        "What is your favorite movie?",
        "What is your favorite food?",
        "What is the name of your best childhood friend?",
        "In what city did you meet your spouse/partner?",
        "What is your favorite sports team?",
        "What was your high school mascot?",
        "What is the name of the street you grew up on?",
        "What is your favorite color?",
        "What is your father's middle name?"
    ]


    # Check if the old 'test_history' table exists and rename it for migration
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='test_history'")
    if cursor.fetchone():
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activity_log'")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE test_history RENAME TO activity_log")
            logging.info("Migrated table 'test_history' to 'activity_log'.")

    # Activity Log table (formerly test_history)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        category TEXT,
        action TEXT,
        severity TEXT,
        result TEXT,
        target TEXT,
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)

    # Add new columns for backward compatibility if migrating from the old schema.
    # This ensures that if the app is updated with an old DB, it doesn't crash.
    _add_column_if_not_exists(cursor, "activity_log", "category", "TEXT")
    _add_column_if_not_exists(cursor, "activity_log", "action", "TEXT")
    _add_column_if_not_exists(cursor, "activity_log", "details", "TEXT")
    _add_column_if_not_exists(cursor, "activity_log", "severity", "TEXT")
    _add_column_if_not_exists(cursor, "activity_log", "result", "TEXT")

    # Login history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)

    # AI Chat History table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ai_chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_id TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)
    # Index for faster history retrieval
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_history_session ON ai_chat_history(user_id, session_id)")

    # SSH Connections table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ssh_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        username TEXT NOT NULL,
        password BLOB,
        private_key BLOB
    );
    """)


    conn.commit()
    conn.close()
    logging.info("Database tables created or already exist.")

def create_admin_user():
    """Creates the default admin user if it doesn't already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the admin user already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", ('admin',))
    if cursor.fetchone():
        logging.info("Admin user already exists.")
        conn.close()
        return

    # If admin does not exist, create it
    admin_username = "admin"
    admin_password = "P@ssw0rd1234567890"
    admin_email = "admin@zurvan.local"
    hashed_password = hash_password(admin_password)

    cursor.execute("""
    INSERT INTO users (username, email, password_hash, is_admin, is_active)
    VALUES (?, ?, ?, 1, 1)
    """, (admin_username, admin_email, hashed_password))

    conn.commit()
    conn.close()
    logging.info("Default admin user created successfully.")

def verify_user(username, password, is_status_check=False):
    """
    Verifies user credentials and checks for lockouts.
    Returns the user row on success.
    Returns None on password mismatch.
    Returns a string 'locked:...' if the account is locked.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        if not is_status_check:
            log_login_event(username, 'Failed Login (User not found)')
        conn.close()
        return None

    # Check if locked
    if user['lockout_until']:
        try:
            lockout_end_time = datetime.fromisoformat(user['lockout_until'])
            if lockout_end_time > datetime.now():
                conn.close()
                return f"locked:{user['lockout_until']}"
        except (ValueError, TypeError):
            logging.error(f"Could not parse lockout_until timestamp '{user['lockout_until']}' for user '{username}'.")

    # Verify password
    hashed_password = hash_password(password)
    if user['password_hash'] == hashed_password and user['is_active'] == 1:
        clear_login_attempts(user['id']) # Success, clear attempts
        log_login_event(username, 'Successful Login', user['id'], cursor=cursor)
        conn.commit()
        conn.close()
        return user
    else:
        # Do not register a failed attempt for a status check or an already inactive user
        if not is_status_check and user['is_active'] == 1:
            log_login_event(username, 'Failed Login (Incorrect Password)', user['id'], cursor=cursor)
            register_failed_login_attempt(username, cursor=cursor) # Failure, record attempt
        elif is_status_check:
            pass # Do nothing on a status check
        else:
            log_login_event(username, 'Failed Login (Account Inactive)', user['id'], cursor=cursor)
        conn.commit()
        conn.close()
        return None

def verify_password_only(user_id, password_to_check):
    """
    Verifies a password against the stored hash for a given user ID without
    logging any attempts. Returns True if the password is correct, False otherwise.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return False

    hashed_password_to_check = hash_password(password_to_check)
    return user['password_hash'] == hashed_password_to_check

def register_failed_login_attempt(username, cursor=None):
    """Implements the progressive lockout logic. Can use an existing cursor or create a new connection."""
    conn = None
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()

    cursor.execute("SELECT id, failed_login_attempts, lockout_level FROM users WHERE username = ? AND is_active = 1", (username,))
    user = cursor.fetchone()

    if user:
        user_id = user['id']
        new_attempts = (user['failed_login_attempts'] or 0) + 1
        current_level = user['lockout_level'] or 0

        if new_attempts >= 3:
            new_level = current_level + 1
            lockout_minutes = 0

            if new_level == 1: lockout_minutes = 3
            elif new_level == 2: lockout_minutes = 6
            elif new_level == 3: lockout_minutes = 9
            elif new_level == 4: lockout_minutes = 15
            else: # new_level >= 5, deactivate account
                cursor.execute("UPDATE users SET is_active = 0, failed_login_attempts = 0, lockout_level = ? WHERE id = ?", (new_level, user_id))
                logging.warning(f"User '{username}' (ID: {user_id}) has been deactivated due to excessive failed login attempts.")
                log_login_event(username, "Account Deactivated", user_id, cursor=cursor)
                return # Exit early, no lockout time to set

            lockout_time = datetime.now() + timedelta(minutes=lockout_minutes)
            cursor.execute(
                "UPDATE users SET failed_login_attempts = 0, lockout_level = ?, lockout_until = ? WHERE id = ?",
                (new_level, lockout_time.isoformat(), user_id)
            )
            logging.warning(f"User '{username}' (ID: {user_id}) locked out for {lockout_minutes} minutes (Level {new_level}).")
            log_login_event(username, f"Account Locked ({lockout_minutes} mins)", user_id, cursor=cursor)
        else:
            # Just increment the attempt counter if it's below the threshold
            cursor.execute("UPDATE users SET failed_login_attempts = ? WHERE id = ?", (new_attempts, user_id))

    if conn:
        conn.commit()
        conn.close()

def clear_login_attempts(user_id):
    """Resets failed login attempts and lockout level for a user upon successful login."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET failed_login_attempts = 0, lockout_until = NULL, lockout_level = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def check_username_or_email_exists(username, email):
    """Checks if a username or email already exists in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
    exists = cursor.fetchone()

    conn.close()
    return exists is not None

def create_user(username, email, password):
    """Creates a new user in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    hashed_password = hash_password(password)

    cursor.execute("""
        INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)
    """, (username, email, hashed_password))

    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def add_security_questions(user_id, questions_with_answers):
    """Adds security questions and their hashed answers for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()

    for q_id, answer in questions_with_answers:
        hashed_answer = hash_password(answer.lower().strip())
        cursor.execute("""
            INSERT INTO security_questions (user_id, question_id, answer_hash)
            VALUES (?, ?, ?)
        """, (user_id, q_id, hashed_answer))

    conn.commit()
    conn.close()

def get_all_users():
    """Retrieves all users from the database for the admin panel."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, is_admin, is_active, full_name, age, job_title, avatar FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

def get_user_by_id(user_id):
    """Retrieves a single user by their ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def update_user_profile(user_id, full_name, age, job_title):
    """Updates the profile information for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Ensure age is an integer or None
        age_int = int(age) if age else None
    except (ValueError, TypeError):
        age_int = None # Set to None if conversion fails
        logging.warning(f"Could not convert age '{age}' to integer for user_id {user_id}. Setting to NULL.")

    cursor.execute("""
        UPDATE users
        SET full_name = ?, age = ?, job_title = ?
        WHERE id = ?
    """, (full_name, age_int, job_title, user_id))
    conn.commit()
    conn.close()

def update_user_username(user_id, new_username):
    """Updates the username for a given user, checking for uniqueness."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # This will raise sqlite3.IntegrityError if the username already exists,
    # which can be caught by the calling UI function.
    cursor.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
    conn.commit()
    conn.close()

def update_user_email(user_id, new_email):
    """Updates the email for a given user, checking for uniqueness."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # This will raise sqlite3.IntegrityError if the email already exists.
    cursor.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
    conn.commit()
    conn.close()

def update_user_avatar(user_id, avatar_data):
    """Updates the avatar for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET avatar = ? WHERE id = ?", (avatar_data, user_id))
    conn.commit()
    conn.close()

def set_user_active_status(user_id, is_active):
    """Updates the is_active status for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (int(is_active), user_id))
    conn.commit()
    conn.close()

def set_user_admin_status(user_id, is_admin):
    """Updates the is_admin status for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id))
    conn.commit()
    conn.close()

def update_user_password(user_id, new_password):
    """Updates the password for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(new_password)
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user_id))
    conn.commit()
    conn.close()

def update_user_pin(user_id, new_pin):
    """Updates the App Lock PIN for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    pin_hash = hash_password(new_pin) if new_pin else None
    cursor.execute("UPDATE users SET pin_hash = ? WHERE id = ?", (pin_hash, user_id))
    conn.commit()
    conn.close()

def set_otp_secret(user_id, secret):
    """Saves or clears the OTP secret for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET otp_secret = ? WHERE id = ?", (secret, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    """Deletes a user and all their related data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Use a transaction to ensure all or nothing is deleted
    try:
        cursor.execute("BEGIN")
        # Delete from tables with foreign key constraints first
        cursor.execute("DELETE FROM security_questions WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM activity_log WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM login_history WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM ai_chat_history WHERE user_id = ?", (user_id,))
        # Finally, delete the user
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        raise e # Re-raise the exception to be handled by the caller
    finally:
        conn.close()

def update_user_app_lock_settings(user_id, timeout_minutes, unlock_method):
    """Updates the app lock settings for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET app_lock_timeout = ?, app_unlock_method = ?
        WHERE id = ?
    """, (timeout_minutes, unlock_method, user_id))
    conn.commit()
    conn.close()

def clear_user_pin(user_id):
    """Clears the App Lock PIN for a given user, forcing them to set a new one."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET pin_hash = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def get_user_by_username_or_email(identifier):
    """Fetches a user by their username or email."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1", (identifier, identifier))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_security_questions(user_id):
    """Fetches the question IDs for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT question_id FROM security_questions WHERE user_id = ?", (user_id,))
    question_ids = [row[0] for row in cursor.fetchall()]
    conn.close()
    return question_ids

def verify_security_answers(user_id, answers_dict):
    """
    Verifies a dictionary of {question_id: answer} against the database.
    Returns True if all answers are correct, False otherwise.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    if len(answers_dict) == 0:
        return False

    for q_id, answer in answers_dict.items():
        hashed_answer = hash_password(answer.lower().strip())
        cursor.execute("""
            SELECT id FROM security_questions
            WHERE user_id = ? AND question_id = ? AND answer_hash = ?
        """, (user_id, q_id, hashed_answer))

        if not cursor.fetchone():
            conn.close()
            return False # One incorrect answer is enough to fail

    conn.close()
    return True # All answers were correct

def log_login_event(username, event_type, user_id=None, cursor=None):
    """Logs a login-related event to the history table and activity log. Can use an existing cursor."""
    conn = None
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO login_history (user_id, username, event_type)
        VALUES (?, ?, ?)
    """, (user_id, username, event_type))

    # Also log to the main activity log for session tracking and auditing
    if user_id:
        # Map event_type from login_history to a more structured activity_log entry
        if event_type == 'Successful Login':
            log_activity(user_id=user_id, category='Authentication', action='User Login', target=username, result='Success', severity='Low', cursor=cursor)
        elif event_type.startswith('Failed Login'):
             log_activity(user_id=user_id, category='Authentication', action='User Login', target=username, result='Failure', severity='Medium', details=event_type, cursor=cursor)
        elif event_type == 'Account Deactivated':
             log_activity(user_id=user_id, category='Authentication', action='Account Deactivated', target=username, result='Success', severity='Critical', details="Account deactivated due to excessive failed login attempts.", cursor=cursor)
        elif event_type.startswith('Account Locked'):
             log_activity(user_id=user_id, category='Authentication', action='Account Locked', target=username, result='Success', severity='High', details=event_type, cursor=cursor)

    if conn:
        conn.commit()
        conn.close()

def get_login_history(username_filter=None):
    """Retrieves login history, optionally filtered by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT strftime('%Y-%m-%d %H:%M:%S', timestamp) as ts, username, event_type FROM login_history"
    params = []

    if username_filter:
        query += " WHERE username = ?"
        params.append(username_filter)

    query += " ORDER BY timestamp DESC"

    cursor.execute(query, params)
    history = cursor.fetchall()
    conn.close()
    return history

def get_latest_session_id(user_id):
    """Retrieves the most recent session_id for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT session_id FROM ai_chat_history
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def log_activity(user_id, category, action, target, details="", severity="INFO", result="SUCCESS", cursor=None):
    """Logs a user activity to the activity_log table. Can use an existing cursor."""
    conn = None
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO activity_log (user_id, category, action, severity, result, target, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, category, action, severity, result, target, details))

    if conn:
        conn.commit()
        conn.close()

def get_activity_log(user_id=None, search_term="", category_filter=None, severity_filter=None, result_filter=None, date_from=None, date_to=None):
    """
    Retrieves the activity log with extensive filtering options.
    If user_id is provided, it filters for that user. Otherwise, it retrieves for all users (for admin).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    params = []
    where_clauses = []

    query = """
        SELECT a.id, a.timestamp, u.username, a.category, a.action, a.severity, a.result, a.target, a.details
        FROM activity_log a
        JOIN users u ON a.user_id = u.id
    """

    if user_id:
        where_clauses.append("a.user_id = ?")
        params.append(user_id)

    if search_term:
        where_clauses.append("(a.action LIKE ? OR a.target LIKE ? OR a.details LIKE ? OR u.username LIKE ?)")
        params.extend([f'%{search_term}%'] * 4)

    if category_filter and category_filter != "All":
        where_clauses.append("a.category = ?")
        params.append(category_filter)

    if severity_filter and severity_filter != "All":
        where_clauses.append("a.severity = ?")
        params.append(severity_filter)

    if result_filter and result_filter != "All":
        where_clauses.append("a.result = ?")
        params.append(result_filter)

    if date_from:
        where_clauses.append("date(a.timestamp) >= date(?)")
        params.append(date_from)

    if date_to:
        where_clauses.append("date(a.timestamp) <= date(?)")
        params.append(date_to)


    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += " ORDER BY a.timestamp DESC"

    cursor.execute(query, tuple(params))
    log_entries = cursor.fetchall()
    conn.close()
    return log_entries


def get_user_session_info(user_id):
    """
    Calculates session information for a given user, including last visit
    and total session duration.

    Args:
        user_id (int): The ID of the user.

    Returns:
        dict: A dictionary containing 'last_login' and 'total_duration_str'.
    """
    conn = get_db_connection()
    try:
        # Get all login and logout events for the user
        cursor = conn.execute(
            "SELECT timestamp, action FROM activity_log WHERE user_id = ? AND (action = 'User Login' OR action = 'User Logout') ORDER BY timestamp ASC",
            (user_id,)
        )
        events = cursor.fetchall()

        if not events:
            return {'last_login': 'Never', 'total_duration_str': 'N/A'}

        total_duration = timedelta(0)
        last_login_time = None
        last_visit_time = None

        for event in events:
            try:
                event_time = datetime.fromisoformat(event['timestamp'])
                action = event['action']
            except (ValueError, TypeError):
                continue # Skip malformed records

            if action == 'User Login':
                # If there's a pending login without a logout, the old session timer is just overwritten.
                # This is correct behavior, as we can't calculate the duration of an unterminated session.
                last_login_time = event_time
                last_visit_time = event_time # Keep track of the latest login time
            elif action == 'User Logout' and last_login_time:
                # If we find a logout and have a pending login, calculate duration
                session_duration = event_time - last_login_time
                total_duration += session_duration
                last_login_time = None # Reset for the next session

        # Format total duration
        total_seconds = int(total_duration.total_seconds())
        days, remainder = divmod(total_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        duration_str = ""
        if days > 0:
            duration_str += f"{days}d "
        duration_str += f"{hours:02}:{minutes:02}:{seconds:02}"

        return {
            'last_login': last_visit_time.strftime('%Y-%m-%d %H:%M:%S') if last_visit_time else 'Never',
            'total_duration_str': duration_str
        }

    except sqlite3.Error as e:
        logging.error(f"Database error while getting session info for user {user_id}: {e}", exc_info=True)
        return {'last_login': 'Error', 'total_duration_str': 'Error'}
    finally:
        if conn:
            conn.close()

def delete_history_entry(entry_id):
    """Deletes a specific entry from the activity log table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM activity_log WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

def create_cve_table():
    """Creates the vulnerabilities table in the CVE database if it doesn't exist."""
    # Note: This connects to a separate database file.
    conn = sqlite3.connect("cve.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        cvss_v3_score REAL,
        cvss_v2_score REAL,
        keywords TEXT,
        published_date TEXT
    )
    """)
    # Create an index for faster keyword searches
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_keywords ON vulnerabilities(keywords)")
    conn.commit()
    conn.close()
    logging.info("CVE database table 'vulnerabilities' created or already exists.")

def get_cve_data(filter_text, sort_column, sort_order, page, page_size, cvss_min=None, cvss_max=None, date_from=None, date_to=None):
    """Fetches paginated and sorted CVE data from the offline database with advanced filters."""
    conn = sqlite3.connect("cve.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    offset = page * page_size
    allowed_columns = ['cve_id', 'cvss_v3_score', 'published_date']
    if sort_column not in allowed_columns:
        sort_column = 'published_date'
    sort_order = "DESC" if sort_order.upper() == "DESC" else "ASC"

    # Build the WHERE clause dynamically
    where_clauses = ["description LIKE ?"]
    params = [f'%{filter_text}%']

    if cvss_min is not None:
        where_clauses.append("cvss_v3_score >= ?")
        params.append(cvss_min)
    if cvss_max is not None:
        where_clauses.append("cvss_v3_score <= ?")
        params.append(cvss_max)
    if date_from:
        # Ensure date is in correct format for query (YYYY-MM-DD)
        where_clauses.append("date(published_date) >= date(?)")
        params.append(date_from)
    if date_to:
        where_clauses.append("date(published_date) <= date(?)")
        params.append(date_to)

    where_sql = " AND ".join(where_clauses)

    query = f"SELECT cve_id, description, cvss_v3_score, published_date FROM vulnerabilities WHERE {where_sql} ORDER BY {sort_column} {sort_order} LIMIT ? OFFSET ?"
    params.extend([page_size, offset])

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_cve_total_count(filter_text, cvss_min=None, cvss_max=None, date_from=None, date_to=None):
    """Gets the total number of CVEs that match the filters."""
    conn = sqlite3.connect("cve.db")
    cursor = conn.cursor()

    where_clauses = ["description LIKE ?"]
    params = [f'%{filter_text}%']

    if cvss_min is not None:
        where_clauses.append("cvss_v3_score >= ?")
        params.append(cvss_min)
    if cvss_max is not None:
        where_clauses.append("cvss_v3_score <= ?")
        params.append(cvss_max)
    if date_from:
        where_clauses.append("date(published_date) >= date(?)")
        params.append(date_from)
    if date_to:
        where_clauses.append("date(published_date) <= date(?)")
        params.append(date_to)

    where_sql = " AND ".join(where_clauses)

    cursor.execute(f"SELECT COUNT(*) FROM vulnerabilities WHERE {where_sql}", tuple(params))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def add_chat_message(user_id, session_id, role, content):
    """Adds a new chat message to the AI history table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ai_chat_history (user_id, session_id, role, content)
        VALUES (?, ?, ?, ?)
    """, (user_id, session_id, role, content))
    conn.commit()
    conn.close()

def get_chat_history(user_id, session_id):
    """Retrieves all chat messages for a given user and session."""
    if not session_id:
        return []
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT role, content FROM ai_chat_history
        WHERE user_id = ? AND session_id = ?
        ORDER BY timestamp ASC
    """, (user_id, session_id))
    history = cursor.fetchall()
    conn.close()
    return history

# --- SSH Connection Management ---

def add_ssh_connection(name, host, port, username, password=None, private_key=None):
    """Adds a new SSH connection to the database, encrypting sensitive data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    enc_password = encrypt_data(password) if password else None
    enc_private_key = encrypt_data(private_key) if private_key else None

    cursor.execute("""
        INSERT INTO ssh_connections (name, host, port, username, password, private_key)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, host, port, username, enc_password, enc_private_key))

    conn.commit()
    conn.close()

def update_ssh_connection(conn_id, name, host, port, username, password=None, private_key=None):
    """Updates an existing SSH connection."""
    conn = get_db_connection()
    cursor = conn.cursor()

    enc_password = encrypt_data(password) if password else None
    enc_private_key = encrypt_data(private_key) if private_key else None

    cursor.execute("""
        UPDATE ssh_connections
        SET name = ?, host = ?, port = ?, username = ?, password = ?, private_key = ?
        WHERE id = ?
    """, (name, host, port, username, enc_password, enc_private_key, conn_id))

    conn.commit()
    conn.close()

def delete_ssh_connection(conn_id):
    """Deletes an SSH connection."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ssh_connections WHERE id = ?", (conn_id,))
    conn.commit()
    conn.close()

def get_ssh_connection(conn_id):
    """Retrieves a single, decrypted SSH connection."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ssh_connections WHERE id = ?", (conn_id,))
    conn_data = cursor.fetchone()
    conn.close()

    if not conn_data:
        return None

    # Decrypt sensitive fields
    decrypted_conn = dict(conn_data)
    if decrypted_conn.get('password'):
        decrypted_conn['password'] = decrypt_data(decrypted_conn['password']).decode('utf-8')
    if decrypted_conn.get('private_key'):
        decrypted_conn['private_key'] = decrypt_data(decrypted_conn['private_key']).decode('utf-8')

    return decrypted_conn

def get_all_ssh_connections():
    """Retrieves all SSH connections (without decrypting credentials)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Fetch all columns needed for display and for later retrieval
    cursor.execute("SELECT id, name, host, port, username FROM ssh_connections ORDER BY name")
    connections = cursor.fetchall()
    conn.close()
    return connections

def initialize_database():
    """
    Initializes the database: creates tables and the default admin user.
    This function should be called once when the application starts.
    """
    logging.info("Initializing database...")
    create_tables()
    create_admin_user()
    create_cve_table()
    logging.info("Database initialization complete.")

if __name__ == '__main__':
    # This allows the script to be run directly to set up the database
    initialize_database()
    print(f"Database '{DATABASE_NAME}' initialized successfully.")
