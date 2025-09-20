import sqlite3
import hashlib
import os
import logging
from datetime import datetime, timedelta

DATABASE_NAME = "gscapy_user_data.db"

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

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


    # Test history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS test_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        test_type TEXT NOT NULL,
        target TEXT NOT NULL,
        results TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
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
    admin_password = "F@rh@dyan2281251462"
    admin_email = "admin@gscapy.local"
    hashed_password = hash_password(admin_password)

    cursor.execute("""
    INSERT INTO users (username, email, password_hash, is_admin, is_active)
    VALUES (?, ?, ?, 1, 1)
    """, (admin_username, admin_email, hashed_password))

    conn.commit()
    conn.close()
    logging.info("Default admin user created successfully.")

def verify_user(username, password):
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
        conn.close()
        return user
    else:
        # Do not register a failed attempt for an already inactive user
        if user['is_active'] == 1:
            register_failed_login_attempt(username) # Failure, record attempt
        conn.close()
        return None

def register_failed_login_attempt(username):
    """Implements the progressive lockout logic."""
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
            if new_level >= 6:
                # Deactivate account after 5 lockouts (3, 6, 9, 12, 15 mins)
                cursor.execute("UPDATE users SET is_active = 0, failed_login_attempts = 0, lockout_level = ? WHERE id = ?", (new_level, user_id))
                logging.warning(f"User '{username}' (ID: {user_id}) has been deactivated due to excessive failed login attempts.")
            else:
                # Set progressive lockout time and reset attempt counter for the next cycle
                lockout_minutes = new_level * 3
                lockout_time = datetime.now() + timedelta(minutes=lockout_minutes)
                cursor.execute(
                    "UPDATE users SET failed_login_attempts = 0, lockout_level = ?, lockout_until = ? WHERE id = ?",
                    (new_level, lockout_time, user_id)
                )
                logging.warning(f"User '{username}' (ID: {user_id}) locked out for {lockout_minutes} minutes (Level {new_level}).")
        else:
            # Just increment the attempt counter if it's below the threshold
            cursor.execute("UPDATE users SET failed_login_attempts = ? WHERE id = ?", (new_attempts, user_id))

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
    cursor.execute("SELECT id, username, email, is_admin, is_active, full_name, age, job_title FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

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

def update_user_password(user_id, new_password):
    """Updates the password for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(new_password)
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user_id))
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

def log_test_to_history(user_id, test_type, target, results):
    """Logs a completed test or action to the history table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO test_history (user_id, test_type, target, results)
        VALUES (?, ?, ?, ?)
    """, (user_id, test_type, target, results))
    conn.commit()
    conn.close()

def get_test_history(user_id=None):
    """
    Retrieves test history.
    If user_id is provided, fetches for a specific user.
    Otherwise, fetches all history for all users (admin view).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    if user_id:
        # For a specific user, we don't need to join with the users table
        cursor.execute("SELECT id, timestamp, 'N/A' as username, test_type, target, results FROM test_history WHERE user_id = ? ORDER BY timestamp DESC", (user_id,))
    else:
        # For the admin view, we want to join to get the username
        cursor.execute("""
            SELECT h.id, h.timestamp, u.username, h.test_type, h.target, h.results
            FROM test_history h
            JOIN users u ON h.user_id = u.id
            ORDER BY h.timestamp DESC
        """)
    history = cursor.fetchall()
    conn.close()
    return history

def delete_history_entry(entry_id):
    """Deletes a specific entry from the test history table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM test_history WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

def initialize_database():
    """
    Initializes the database: creates tables and the default admin user.
    This function should be called once when the application starts.
    """
    logging.info("Initializing database...")
    create_tables()
    create_admin_user()
    logging.info("Database initialization complete.")

if __name__ == '__main__':
    # This allows the script to be run directly to set up the database
    initialize_database()
    print(f"Database '{DATABASE_NAME}' initialized successfully.")
