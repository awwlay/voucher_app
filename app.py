from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta,UTC
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from dotenv import load_dotenv
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.security import check_password_hash, generate_password_hash

from forms import (
    AccountForm,
    DeleteForm,
    LoginForm,
    LogoutForm,
    OrderForm,
    PasswordForm,
    RegisterForm,
    PAYMENT_STATUSES,
    STATUSES,
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "workshop.db"

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_SECURE_COOKIES", "0") == "1"
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = app.config["SESSION_COOKIE_SECURE"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"
login_manager.session_protection = "strong"
csrf = CSRFProtect(app)

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_ATTEMPTS: dict[str, list[float]] = {}


@dataclass
class User(UserMixin):
    id: int
    username: str


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    db = get_db()
    row = db.execute(
        "SELECT id, username FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return None
    return User(id=int(row["id"]), username=row["username"])


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def add_security_headers(response: Any) -> Any:
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )
    return response


def init_db() -> None:
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, phone_number)
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            voucher_number TEXT NOT NULL,
            customer_id INTEGER NOT NULL,
            order_date TEXT NOT NULL,
            deposit REAL NOT NULL DEFAULT 0,
            total_amount REAL NOT NULL DEFAULT 0,
            balance REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            payment_status TEXT NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        );

        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            total REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
        );
        """)

    db.commit()
    ensure_legacy_columns(db)


def ensure_legacy_columns(db: sqlite3.Connection) -> None:
    order_cols = {
        row["name"] for row in db.execute("PRAGMA table_info(orders)").fetchall()
    }
    customer_cols = {
        row["name"] for row in db.execute("PRAGMA table_info(customers)").fetchall()
    }

    if "user_id" not in order_cols:
        db.execute("ALTER TABLE orders ADD COLUMN user_id INTEGER")
        first_user = db.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if first_user:
            db.execute(
                "UPDATE orders SET user_id = ? WHERE user_id IS NULL",
                (first_user["id"],),
            )

    if "user_id" not in customer_cols:
        db.execute("ALTER TABLE customers ADD COLUMN user_id INTEGER")
        first_user = db.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if first_user:
            db.execute(
                "UPDATE customers SET user_id = ? WHERE user_id IS NULL",
                (first_user["id"],),
            )

    db.commit()


def next_voucher_number(user_id: int) -> str:
    db = get_db()
    row = db.execute(
        "SELECT voucher_number FROM orders WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    if not row:
        return "FW-0001"
    current = row["voucher_number"]
    try:
        serial = int(current.split("-")[1]) + 1
    except (IndexError, ValueError):
        serial = 1
    return f"FW-{serial:04d}"


def upsert_customer(user_id: int, name: str, phone_number: str) -> int:
    db = get_db()
    customer = db.execute(
        "SELECT id, name FROM customers WHERE user_id = ? AND phone_number = ?",
        (user_id, phone_number),
    ).fetchone()
    if customer:
        if customer["name"] != name:
            db.execute(
                "UPDATE customers SET name = ? WHERE id = ?", (name, customer["id"])
            )
            db.commit()
        return int(customer["id"])

    now = datetime.now(UTC).isoformat()
    cur = db.execute(
        "INSERT INTO customers (user_id, name, phone_number, created_at) VALUES (?, ?, ?, ?)",
        (user_id, name, phone_number, now),
    )
    db.commit()
    return int(cur.lastrowid)


def fetch_order(order_id: int, user_id: int) -> dict[str, Any] | None:
    db = get_db()
    order_row = db.execute(
        """
        SELECT o.*, c.name AS customer_name, c.phone_number
        FROM orders o
        JOIN customers c ON c.id = o.customer_id
        WHERE o.id = ? AND o.user_id = ?
        """,
        (order_id, user_id),
    ).fetchone()
    if not order_row:
        return None

    items = db.execute(
        "SELECT * FROM order_items WHERE order_id = ? ORDER BY id ASC", (order_id,)
    ).fetchall()

    return {
        "id": order_row["id"],
        "voucher_number": order_row["voucher_number"],
        "customer_name": order_row["customer_name"],
        "phone_number": order_row["phone_number"],
        "order_date": order_row["order_date"],
        "deposit": order_row["deposit"],
        "total_amount": order_row["total_amount"],
        "balance": order_row["balance"],
        "status": order_row["status"],
        "payment_status": order_row["payment_status"],
        "notes": order_row["notes"] or "",
        "items": [dict(item) for item in items],
    }


def get_login_rate_limit_key(username: str) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    client_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else (request.remote_addr or "unknown")
    )
    return f"{client_ip}:{username.lower() or 'anonymous'}"


def prune_login_attempts(key: str, now: float | None = None) -> list[float]:
    current_time = now if now is not None else time.time()
    attempts = [
        ts
        for ts in LOGIN_ATTEMPTS.get(key, [])
        if current_time - ts < LOGIN_WINDOW_SECONDS
    ]
    if attempts:
        LOGIN_ATTEMPTS[key] = attempts
    else:
        LOGIN_ATTEMPTS.pop(key, None)
    return attempts


def is_login_rate_limited(key: str) -> bool:
    return len(prune_login_attempts(key)) >= MAX_LOGIN_ATTEMPTS


def record_failed_login(key: str) -> None:
    attempts = prune_login_attempts(key)
    attempts.append(time.time())
    LOGIN_ATTEMPTS[key] = attempts


def clear_failed_logins(key: str) -> None:
    LOGIN_ATTEMPTS.pop(key, None)


def normalize_filter_date(value: str) -> str:
    try:
        parsed = datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except (AttributeError, ValueError):
        return ""
    return parsed.isoformat()


def flash_form_errors(form: Any) -> None:
    errors = [message for messages in form.errors.values() for message in messages]
    if errors:
        flash("Please fix: " + "; ".join(errors[:5]), "error")


def parse_date_value(value: str) -> datetime.date | None:
    try:
        return datetime.fromisoformat(value).date()
    except (TypeError, ValueError):
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d").date()
        except (TypeError, ValueError, IndexError):
            return None


def parse_items_payload(value: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


@app.context_processor
def inject_forms() -> dict[str, Any]:
    return {"logout_form": LogoutForm()}


@app.errorhandler(CSRFError)
def handle_csrf_error(_: CSRFError) -> Any:
    flash("Your session expired or the form is invalid. Please try again.", "error")
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login() -> str | Any:
    form = LoginForm()
    init_db()
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        rate_limit_key = get_login_rate_limit_key(username)
        if is_login_rate_limited(rate_limit_key):
            flash(
                "Too many login attempts. Please wait 15 minutes and try again.",
                "error",
            )
            return render_template("login.html", title="Login", form=form), 429
        db = get_db()
        row = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            record_failed_login(rate_limit_key)
            flash("Invalid username or password.", "error")
            return render_template("login.html", title="Login", form=form), 401

        clear_failed_logins(rate_limit_key)
        session.permanent = True
        login_user(User(id=int(row["id"]), username=row["username"]))
        flash("Logged in successfully.", "success")
        return redirect(url_for("index"))

    if request.method == "POST":
        flash_form_errors(form)
    return render_template("login.html", title="Login", form=form)


@app.route("/register", methods=["GET", "POST"])
def register() -> str | Any:
    form = RegisterForm()
    init_db()
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        db = get_db()
        exists = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if exists:
            flash("Username already exists.", "error")
            return render_template("register.html", title="Register", form=form)

        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), datetime.now(UTC).isoformat()),
        )
        db.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    if request.method == "POST":
        flash_form_errors(form)
    return render_template("register.html", title="Register", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout() -> Any:
    form = LogoutForm()
    if not form.validate_on_submit():
        flash_form_errors(form)
        return redirect(url_for("index"))
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile() -> str | Any:
    init_db()
    db = get_db()
    user_id = int(current_user.id)

    user_row = db.execute(
        "SELECT id, username, password_hash, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not user_row:
        logout_user()
        flash("User account not found.", "error")
        return redirect(url_for("login"))

    account_form = AccountForm()
    password_form = PasswordForm()
    if request.method == "GET" or request.form.get("form_type", "").strip() != "account":
        account_form.username.data = user_row["username"]

    if request.method == "POST":
        form_type = request.form.get("form_type", "").strip()

        if form_type == "account":
            if account_form.validate_on_submit():
                new_username = account_form.username.data.strip()
                existing_user = db.execute(
                    "SELECT id FROM users WHERE username = ? AND id != ?",
                    (new_username, user_id),
                ).fetchone()
                if existing_user:
                    flash("That username is already taken.", "error")
                else:
                    db.execute(
                        "UPDATE users SET username = ? WHERE id = ?",
                        (new_username, user_id),
                    )
                    db.commit()
                    login_user(User(id=user_id, username=new_username))
                    flash("Profile updated successfully.", "success")
                    return redirect(url_for("profile"))
            else:
                flash_form_errors(account_form)

        elif form_type == "password":
            if password_form.validate_on_submit():
                if not check_password_hash(
                    user_row["password_hash"], password_form.current_password.data
                ):
                    flash("Current password is incorrect.", "error")
                elif check_password_hash(
                    user_row["password_hash"], password_form.new_password.data
                ):
                    flash(
                        "New password must be different from the current password.",
                        "error",
                    )
                else:
                    db.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ?",
                        (
                            generate_password_hash(password_form.new_password.data),
                            user_id,
                        ),
                    )
                    db.commit()
                    flash("Password updated successfully.", "success")
                    return redirect(url_for("profile"))
            else:
                flash_form_errors(password_form)
        else:
            flash("Profile form is invalid.", "error")

    order_count = db.execute(
        "SELECT COUNT(*) AS c FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchone()["c"]
    customer_count = db.execute(
        "SELECT COUNT(*) AS c FROM customers WHERE user_id = ?",
        (user_id,),
    ).fetchone()["c"]
    total_revenue = db.execute(
        "SELECT COALESCE(SUM(total_amount), 0) AS v FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchone()["v"]
    outstanding = db.execute(
        "SELECT COALESCE(SUM(balance), 0) AS v FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchone()["v"]

    return render_template(
        "profile.html",
        profile=user_row,
        order_count=order_count,
        customer_count=customer_count,
        total_revenue=total_revenue,
        outstanding=outstanding,
        account_form=account_form,
        password_form=password_form,
    )


@app.route("/")
@login_required
def index() -> str:
    init_db()
    db = get_db()
    user_id = int(current_user.id)

    search = request.args.get("search", "").strip()
    status = request.args.get("status", "All")
    payment = request.args.get("payment", "All")
    start_date = normalize_filter_date(request.args.get("start_date", ""))
    end_date = normalize_filter_date(request.args.get("end_date", ""))

    if status not in ["All", *STATUSES]:
        status = "All"
    if payment not in ["All", *PAYMENT_STATUSES]:
        payment = "All"

    conditions = ["o.user_id = ?"]
    params: list[Any] = [user_id]

    if search:
        conditions.append(
            "(o.voucher_number LIKE ? OR c.name LIKE ? OR c.phone_number LIKE ? OR EXISTS (SELECT 1 FROM order_items i WHERE i.order_id = o.id AND i.item_name LIKE ?))"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])

    if status != "All":
        conditions.append("o.status = ?")
        params.append(status)

    if payment != "All":
        conditions.append("o.payment_status = ?")
        params.append(payment)

    if start_date:
        conditions.append("o.order_date >= ?")
        params.append(start_date)

    if end_date:
        conditions.append("o.order_date <= ?")
        params.append(end_date)

    where_clause = f"WHERE {' AND '.join(conditions)}"

    orders = db.execute(
        f"""
        SELECT o.id, o.voucher_number, o.order_date, o.total_amount, o.status, o.payment_status,
               c.name AS customer_name, c.phone_number
        FROM orders o
        JOIN customers c ON c.id = o.customer_id
        {where_clause}
        ORDER BY o.created_at DESC
        """,
        params,
    ).fetchall()

    customers = db.execute(
        "SELECT id, name, phone_number, created_at FROM customers WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()

    return render_template(
        "index.html",
        orders=orders,
        customers=customers,
        delete_form=DeleteForm(),
        statuses=STATUSES,
        payment_statuses=PAYMENT_STATUSES,
        filters={
            "search": search,
            "status": status,
            "payment": payment,
            "start_date": start_date,
            "end_date": end_date,
        },
    )


@app.route("/analytics")
@login_required
def analytics() -> str:
    db = get_db()
    user_id = int(current_user.id)

    rows = db.execute(
        """
        SELECT o.status, o.payment_status, o.order_date, o.total_amount, o.balance
        FROM orders o
        WHERE o.user_id = ?
        """,
        (user_id,),
    ).fetchall()
    df = pd.DataFrame([dict(r) for r in rows])

    total_orders = db.execute(
        "SELECT COUNT(*) AS c FROM orders WHERE user_id = ?", (user_id,)
    ).fetchone()["c"]
    total_customers = db.execute(
        "SELECT COUNT(*) AS c FROM customers WHERE user_id = ?", (user_id,)
    ).fetchone()["c"]
    total_revenue = db.execute(
        "SELECT COALESCE(SUM(total_amount), 0) AS v FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchone()["v"]
    outstanding = db.execute(
        "SELECT COALESCE(SUM(balance), 0) AS v FROM orders WHERE user_id = ?",
        (user_id,),
    ).fetchone()["v"]

    if df.empty:
        status_labels = []
        status_values = []
        payment_labels = []
        payment_values = []
        revenue_labels = []
        revenue_values = []
        yearly_revenue_labels = []
        yearly_revenue_values = []
    else:
        status_counts = (
            df.groupby("status", as_index=False)
            .size()
            .rename(columns={"size": "count"})
        )
        status_labels = status_counts["status"].astype(str).tolist()
        status_values = np.array(status_counts["count"], dtype=int).tolist()

        payment_counts = (
            df.groupby("payment_status", as_index=False)
            .size()
            .rename(columns={"size": "count"})
        )
        payment_labels = payment_counts["payment_status"].astype(str).tolist()
        payment_values = np.array(payment_counts["count"], dtype=int).tolist()

        revenue_df = df.copy()
        revenue_df["month"] = (
            pd.to_datetime(revenue_df["order_date"], errors="coerce")
            .dt.to_period("M")
            .astype(str)
        )

        revenue_df["total_amount"] = pd.to_numeric(
            revenue_df["total_amount"], errors="coerce"
        ).fillna(0.0)
        revenue_df = (
            revenue_df.groupby("month", as_index=False)["total_amount"]
            .sum()
            .sort_values("month")
        )
        revenue_labels = revenue_df["month"].tolist()
        revenue_values = (
            np.array(revenue_df["total_amount"], dtype=float).round(2).tolist()
        )
        revenue_df2 = df.copy()
        revenue_df2["year"] = (
            pd.to_datetime(revenue_df2["order_date"], errors="coerce")
            .dt.to_period("Y")
            .astype(str)
        )
        revenue_df2["total_amount"] = pd.to_numeric(
            revenue_df2["total_amount"], errors="coerce"
        ).fillna(0.0)
        revenue_df2 = (
            revenue_df2.groupby("year", as_index=False)["total_amount"]
            .sum()
            .sort_values("year")
        )
        yearly_revenue_labels = revenue_df2["year"].tolist()
        yearly_revenue_values = (
            np.array(revenue_df2["total_amount"], dtype=float).round(2).tolist()
        )

    return render_template(
        "analytics.html",
        status_labels=status_labels,
        status_values=status_values,
        payment_labels=payment_labels,
        payment_values=payment_values,
        revenue_labels=revenue_labels,
        revenue_values=revenue_values,
        yearly_revenue_labels=yearly_revenue_labels,
        yearly_revenue_values=yearly_revenue_values,
        total_orders=total_orders,
        total_customers=total_customers,
        total_revenue=total_revenue,
        outstanding=outstanding,
    )


@app.route("/orders/new")
@login_required
def new_order() -> str:
    form = OrderForm()
    form.status.data = "Pending"
    form.payment_status.data = "Unpaid"
    form.deposit.data = 0
    return render_template(
        "order_form.html",
        form=form,
        order=None,
        suggested_voucher=next_voucher_number(int(current_user.id)),
        initial_items=[],
    )


@app.route("/orders/<int:order_id>/edit")
@login_required
def edit_order(order_id: int) -> str:
    order = fetch_order(order_id, int(current_user.id))
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("index"))

    form = OrderForm(
        data={
            "order_id": order["id"],
            "customer_name": order["customer_name"],
            "phone_number": order["phone_number"],
            "order_date": parse_date_value(order["order_date"]),
            "status": order["status"],
            "payment_status": order["payment_status"],
            "deposit": order["deposit"],
            "notes": order["notes"],
        }
    )
    form.items_json.data = json.dumps(order["items"])

    return render_template(
        "order_form.html",
        form=form,
        order=order,
        suggested_voucher=order["voucher_number"],
        initial_items=order["items"],
    )


@app.route("/orders/save", methods=["POST"])
@login_required
def save_order() -> Any:
    init_db()
    db = get_db()
    user_id = int(current_user.id)

    form = OrderForm()
    if not form.validate_on_submit():
        flash_form_errors(form)
        order_id = None
        if form.order_id.data:
            try:
                order_id = int(form.order_id.data)
            except ValueError:
                order_id = None
        order = fetch_order(order_id, user_id) if order_id else None
        suggested_voucher = order["voucher_number"] if order else next_voucher_number(user_id)
        return render_template(
            "order_form.html",
            form=form,
            order=order,
            suggested_voucher=suggested_voucher,
            initial_items=parse_items_payload(form.items_json.data),
        ), 400

    order_id = None
    if form.order_id.data:
        try:
            order_id = int(form.order_id.data)
        except ValueError:
            flash("Order ID is invalid.", "error")
            return render_template(
                "order_form.html",
                form=form,
                order=None,
                suggested_voucher=next_voucher_number(user_id),
                initial_items=parse_items_payload(form.items_json.data),
            ), 400

    customer_name = form.customer_name.data.strip()
    phone_number = form.phone_number.data.strip()
    order_date = form.order_date.data.isoformat()
    status = form.status.data
    payment_status = form.payment_status.data
    notes = (form.notes.data or "").strip()
    clean_items = form.clean_items
    deposit = float(form.deposit.data or 0)
    total_amount = round(sum(item["total"] for item in clean_items), 2)

    if deposit > total_amount:
        form.deposit.errors.append("Deposit cannot be greater than the total amount.")
        flash_form_errors(form)
        order = fetch_order(order_id, user_id) if order_id else None
        suggested_voucher = order["voucher_number"] if order else next_voucher_number(user_id)
        return render_template(
            "order_form.html",
            form=form,
            order=order,
            suggested_voucher=suggested_voucher,
            initial_items=parse_items_payload(form.items_json.data),
        ), 400

    balance = round(total_amount - deposit, 2)
    customer_id = upsert_customer(user_id, customer_name, phone_number)
    now = datetime.now(UTC).isoformat()

    if order_id:
        existing = db.execute(
            "SELECT voucher_number FROM orders WHERE id = ? AND user_id = ?",
            (order_id, user_id),
        ).fetchone()
        if not existing:
            flash("Order not found.", "error")
            return redirect(url_for("index"))

        db.execute(
            """
            UPDATE orders
            SET customer_id = ?, order_date = ?, deposit = ?, total_amount = ?, balance = ?, status = ?, payment_status = ?, notes = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                customer_id,
                order_date,
                deposit,
                total_amount,
                balance,
                status,
                payment_status,
                notes,
                order_id,
                user_id,
            ),
        )
        db.execute("DELETE FROM order_items WHERE order_id = ?", (order_id,))
        active_order_id = int(order_id)
    else:
        voucher_number = next_voucher_number(user_id)
        cur = db.execute(
            """
            INSERT INTO orders (user_id, voucher_number, customer_id, order_date, deposit, total_amount, balance, status, payment_status, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                voucher_number,
                customer_id,
                order_date,
                deposit,
                total_amount,
                balance,
                status,
                payment_status,
                notes,
                now,
            ),
        )
        active_order_id = int(cur.lastrowid)

    for item in clean_items:
        db.execute(
            """
            INSERT INTO order_items (order_id, item_name, quantity, unit_price, total)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                active_order_id,
                item["item_name"],
                item["quantity"],
                item["unit_price"],
                item["total"],
            ),
        )

    db.commit()
    flash("Order saved successfully.", "success")
    return redirect(url_for("voucher", order_id=active_order_id))


@app.route("/orders/<int:order_id>/delete", methods=["POST"])
@login_required
def delete_order(order_id: int) -> Any:
    form = DeleteForm()
    if not form.validate_on_submit():
        flash_form_errors(form)
        return redirect(url_for("index"))

    db = get_db()
    db.execute("DELETE FROM order_items WHERE order_id = ?", (order_id,))
    db.execute(
        "DELETE FROM orders WHERE id = ? AND user_id = ?",
        (order_id, int(current_user.id)),
    )
    db.commit()
    flash("Order deleted.", "success")
    return redirect(url_for("index"))


@app.route("/voucher/<int:order_id>")
@login_required
def voucher(order_id: int) -> str | Any:
    order = fetch_order(order_id, int(current_user.id))
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("index"))
    return render_template("voucher.html", order=order)


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(
        host=os.environ.get("FLASK_RUN_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_RUN_PORT", "5000")),
        debug=False,
    )
