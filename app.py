from flask import Flask, render_template, request, redirect, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import re
import os
from dotenv import load_dotenv
app = Flask(__name__)

load_dotenv()

app.secret_key = os.getenv("SECRET_KEY")
# Encryption key
# Use your NEW private Fernet key here
encryption_key = os.getenv("ENCRYPTION_KEY")
cipher = Fernet(encryption_key)


# ---------------- MYSQL CONNECTION ----------------

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="password_manager"
)


# ---------------- HOME / LOGIN ----------------

@app.route("/")
def home():
    return render_template("login.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        cursor = db.cursor()

        query = """
        INSERT INTO users (username, email, password_hash)
        VALUES (%s, %s, %s)
        """

        cursor.execute(
            query,
            (username, email, password_hash)
        )

        db.commit()
        cursor.close()

        return "Registration successful! <a href='/'>Login here</a>"

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["POST"])
def login():

    email = request.form["email"]
    password = request.form["password"]

    cursor = db.cursor(dictionary=True)

    query = "SELECT * FROM users WHERE email = %s"

    cursor.execute(query, (email,))

    user = cursor.fetchone()

    cursor.close()

    if user and check_password_hash(
        user["password_hash"],
        password
    ):

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect("/dashboard")

    return "Invalid email or password"


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/")

    cursor = db.cursor(dictionary=True)

    query = """
    SELECT id, website, account_username, strength, created_at
    FROM passwords
    WHERE user_id = %s
    """

    cursor.execute(
        query,
        (session["user_id"],)
    )

    passwords = cursor.fetchall()

    cursor.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        passwords=passwords
    )


# ---------------- ADD PASSWORD ----------------

@app.route("/add-password", methods=["GET", "POST"])
def add_password():

    if "user_id" not in session:
        return redirect("/")

    if request.method == "POST":

        website = request.form["website"]
        account_username = request.form["account_username"]
        password_value = request.form["password_value"]

        # Encrypt password before storing
        encrypted_password = cipher.encrypt(
            password_value.encode()
        ).decode()

        # Password strength
        score = 0

        if len(password_value) >= 8:
            score += 1

        if re.search(r"[A-Z]", password_value):
            score += 1

        if re.search(r"[a-z]", password_value):
            score += 1

        if re.search(r"[0-9]", password_value):
            score += 1

        if re.search(r"[^A-Za-z0-9]", password_value):
            score += 1

        if score >= 4:
            strength = "Strong"

        elif score >= 3:
            strength = "Medium"

        else:
            strength = "Weak"

        cursor = db.cursor()

        query = """
        INSERT INTO passwords
        (user_id, website, account_username, password_value, strength)
        VALUES (%s, %s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (
                session["user_id"],
                website,
                account_username,
                encrypted_password,
                strength
            )
        )

        db.commit()
        cursor.close()

        return redirect("/dashboard")

    return render_template("add_password.html")


# ---------------- EDIT PASSWORD ----------------

@app.route("/edit-password/<int:password_id>", methods=["GET", "POST"])
def edit_password(password_id):

    if "user_id" not in session:
        return redirect("/")

    cursor = db.cursor(dictionary=True)

    query = """
    SELECT *
    FROM passwords
    WHERE id = %s AND user_id = %s
    """

    cursor.execute(
        query,
        (password_id, session["user_id"])
    )

    item = cursor.fetchone()

    cursor.close()

    if not item:
        return "Password entry not found"

    if request.method == "POST":

        website = request.form["website"]
        account_username = request.form["account_username"]
        new_password = request.form["password_value"]

        cursor = db.cursor()

        if new_password:

            # Encrypt new password
            encrypted_password = cipher.encrypt(
                new_password.encode()
            ).decode()

            # Password strength
            score = 0

            if len(new_password) >= 8:
                score += 1

            if re.search(r"[A-Z]", new_password):
                score += 1

            if re.search(r"[a-z]", new_password):
                score += 1

            if re.search(r"[0-9]", new_password):
                score += 1

            if re.search(r"[^A-Za-z0-9]", new_password):
                score += 1

            if score >= 4:
                strength = "Strong"

            elif score >= 3:
                strength = "Medium"

            else:
                strength = "Weak"

            query = """
            UPDATE passwords
            SET website = %s,
                account_username = %s,
                password_value = %s,
                strength = %s
            WHERE id = %s AND user_id = %s
            """

            cursor.execute(
                query,
                (
                    website,
                    account_username,
                    encrypted_password,
                    strength,
                    password_id,
                    session["user_id"]
                )
            )

        else:

            query = """
            UPDATE passwords
            SET website = %s,
                account_username = %s
            WHERE id = %s AND user_id = %s
            """

            cursor.execute(
                query,
                (
                    website,
                    account_username,
                    password_id,
                    session["user_id"]
                )
            )

        db.commit()
        cursor.close()

        return redirect("/dashboard")

    return render_template(
        "edit_password.html",
        item=item
    )


# ---------------- DELETE PASSWORD ----------------

@app.route("/delete-password/<int:password_id>")
def delete_password(password_id):

    if "user_id" not in session:
        return redirect("/")

    cursor = db.cursor()

    query = """
    DELETE FROM passwords
    WHERE id = %s AND user_id = %s
    """

    cursor.execute(
        query,
        (
            password_id,
            session["user_id"]
        )
    )

    db.commit()
    cursor.close()

    return redirect("/dashboard")


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":
    app.run(debug=True)