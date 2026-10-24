import hashlib
import hmac
import secrets
import sqlite3
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

import flet as ft


# =========================================================
# CONFIGURATION
# =========================================================

DB_PATH = Path(__file__).parent / "worthy_bank.db"

PBKDF2_ITERATIONS = 310_000

GREEN = "#176B5B"
DARK_GREEN = "#173B35"
LIGHT_BACKGROUND = "#F4F7FB"
SUCCESS = "#167447"
ERROR = "#B42318"
MUTED = "#667085"

CATEGORIES = [
    "Salary",
    "Business",
    "Food",
    "Transport",
    "Housing",
    "Utilities",
    "Education",
    "Health",
    "Savings",
    "Other",
]

BUDGET_CATEGORIES = [
    "Food",
    "Transport",
    "Housing",
    "Utilities",
    "Education",
    "Health",
    "Other",
]


# =========================================================
# DATABASE CONNECTION
# =========================================================

def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialise_database():
    with connect_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_date TEXT NOT NULL
            )
        """)

        # Original personal-finance tables.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                kind TEXT NOT NULL
                    CHECK(kind IN ('Income', 'Expense')),
                amount_cents INTEGER NOT NULL
                    CHECK(amount_cents > 0),
                category TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                transaction_date TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS savings_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                name TEXT NOT NULL,
                target_cents INTEGER NOT NULL
                    CHECK(target_cents > 0),
                saved_cents INTEGER NOT NULL DEFAULT 0
                    CHECK(saved_cents >= 0),
                created_date TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS budgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id)
                    ON DELETE CASCADE,
                category TEXT NOT NULL,
                month TEXT NOT NULL,
                limit_cents INTEGER NOT NULL
                    CHECK(limit_cents > 0),
                UNIQUE(user_id, category, month)
            )
        """)

        # Banking accounts.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bank_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE
                    REFERENCES users(id) ON DELETE CASCADE,
                account_number TEXT NOT NULL UNIQUE,
                account_type TEXT NOT NULL DEFAULT 'Savings',
                balance_cents INTEGER NOT NULL DEFAULT 0
                    CHECK(balance_cents >= 0),
                status TEXT NOT NULL DEFAULT 'Active'
                    CHECK(status IN ('Active', 'Blocked')),
                created_date TEXT NOT NULL
            )
        """)

        # Banking ledger: deposits, withdrawals and transfers.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bank_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                transaction_type TEXT NOT NULL
                    CHECK(transaction_type IN (
                        'Deposit', 'Withdrawal', 'Transfer In',
                        'Transfer Out'
                    )),
                amount_cents INTEGER NOT NULL
                    CHECK(amount_cents > 0),
                description TEXT NOT NULL DEFAULT '',
                related_account TEXT NOT NULL DEFAULT '',
                transaction_date TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_bank_tx_user_date
            ON bank_transactions(user_id, id DESC)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_user_date
            ON transactions(user_id, transaction_date)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_goals_user
            ON savings_goals(user_id)
        """)

        # Notifications.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                message TEXT NOT NULL,
                created_date TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0
                    CHECK(is_read IN (0, 1))
            )
        """)

        # Audit history for important demo banking actions.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                action TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_date TEXT NOT NULL
            )
        """)

        # Ensure existing customers also receive bank accounts.
        users = conn.execute(
            "SELECT id FROM users"
        ).fetchall()

        for (user_id,) in users:
            create_bank_account_if_missing(conn, user_id)


# =========================================================
# ACCOUNT CREATION AND MIGRATION
# =========================================================

def generate_account_number(conn):
    """Generate a unique 10-digit demo account number."""

    while True:
        number = "10" + "".join(
            secrets.choice("0123456789")
            for _ in range(8)
        )

        existing = conn.execute(
            """
            SELECT 1 FROM bank_accounts
            WHERE account_number = ?
            """,
            (number,),
        ).fetchone()

        if not existing:
            return number


def create_bank_account_if_missing(conn, user_id):
    existing = conn.execute(
        """
        SELECT id FROM bank_accounts
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()

    if existing:
        return

    account_number = generate_account_number(conn)

    conn.execute(
        """
        INSERT INTO bank_accounts (
            user_id,
            account_number,
            account_type,
            balance_cents,
            status,
            created_date
        )
        VALUES (?, ?, 'Savings', 0, 'Active', ?)
        """,
        (
            user_id,
            account_number,
            date.today().isoformat(),
        ),
    )


def get_account(user_id):
    with connect_db() as conn:
        return conn.execute(
            """
            SELECT account_number, account_type,
                   balance_cents, status
            FROM bank_accounts
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()


# =========================================================
# PASSWORD SECURITY
# =========================================================

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return salt.hex() + "$" + digest.hex()


def verify_password(password, stored_hash):
    try:
        salt_hex, expected_hex = stored_hash.split("$", 1)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            PBKDF2_ITERATIONS,
        ).hex()

        return hmac.compare_digest(
            actual_hash,
            expected_hex,
        )

    except (ValueError, TypeError):
        return False


# =========================================================
# REGISTRATION AND LOGIN
# =========================================================

def register_user(email, password):
    email = (email or "").strip().lower()
    password = password or ""

    if (
        len(email) > 254
        or "@" not in email
        or email.startswith("@")
        or email.endswith("@")
        or any(char.isspace() for char in email)
    ):
        return None, "Please enter a valid email address."

    if len(password) < 8:
        return None, "Password must be at least 8 characters."

    if len(password) > 256:
        return None, "Password is too long."

    try:
        with connect_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users (
                    email, password_hash, created_date
                )
                VALUES (?, ?, ?)
                """,
                (
                    email,
                    hash_password(password),
                    date.today().isoformat(),
                ),
            )

            user_id = cursor.lastrowid

            create_bank_account_if_missing(
                conn,
                user_id,
            )

            return user_id, (
                "Account created successfully! "
                "You can now sign in."
            )

    except sqlite3.IntegrityError:
        return None, "An account with this email already exists."

    except sqlite3.Error:
        return None, "Database error. Please try again."


def authenticate_user(email, password):
    email = (email or "").strip().lower()
    password = password or ""

    try:
        with connect_db() as conn:
            user = conn.execute(
                """
                SELECT id, email, password_hash
                FROM users
                WHERE email = ?
                """,
                (email,),
            ).fetchone()

            if not user or not verify_password(
                password,
                user[2],
            ):
                return None

            account = conn.execute(
                """
                SELECT status FROM bank_accounts
                WHERE user_id = ?
                """,
                (user[0],),
            ).fetchone()

            if account is None:
                create_bank_account_if_missing(
                    conn,
                    user[0],
                )
            elif account[0] != "Active":
                return None

            return {
                "id": user[0],
                "email": user[1],
            }

    except sqlite3.Error:
        return None


# =========================================================
# MONEY HELPERS
# =========================================================

def money(cents):
    return f"R{cents / 100:,.2f}"


def parse_cents(raw):
    try:
        amount = Decimal((raw or "").strip())

        if not amount.is_finite() or amount <= 0:
            raise ValueError

        cents = amount * 100

        if cents != cents.to_integral_value():
            raise ValueError

        return int(cents)

    except (
        InvalidOperation,
        ValueError,
        AttributeError,
    ):
        raise ValueError(
            "Enter a valid positive amount, e.g. 150.50."
        )


def create_reference():
    return "WB" + secrets.token_hex(6).upper()


def add_notification(conn, user_id, message):
    conn.execute(
        """
        INSERT INTO notifications (
            user_id, message, created_date
        )
        VALUES (?, ?, ?)
        """,
        (
            user_id,
            message,
            date.today().isoformat(),
        ),
    )


def add_audit_log(conn, user_id, action, details=""):
    conn.execute(
        """
        INSERT INTO audit_logs (
            user_id, action, details, created_date
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            details,
            date.today().isoformat(),
        ),
    )


# =========================================================
# DEPOSIT MONEY
# =========================================================

def deposit_money(user_id, cents, description="Cash deposit"):
    if cents <= 0:
        raise ValueError("Deposit amount must be positive.")

    with connect_db() as conn:
        account = conn.execute(
            """
            SELECT account_number, status
            FROM bank_accounts
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        if account is None:
            raise ValueError("Bank account not found.")

        account_number, status = account

        if status != "Active":
            raise ValueError("This account is not active.")

        conn.execute(
            """
            UPDATE bank_accounts
            SET balance_cents = balance_cents + ?
            WHERE user_id = ?
            """,
            (cents, user_id),
        )

        conn.execute(
            """
            INSERT INTO bank_transactions (
                reference, user_id, transaction_type,
                amount_cents, description,
                related_account, transaction_date
            )
            VALUES (?, ?, 'Deposit', ?, ?, '', ?)
            """,
            (
                create_reference(),
                user_id,
                cents,
                description,
                date.today().isoformat(),
            ),
        )

        add_notification(
            conn,
            user_id,
            f"Demo deposit of {money(cents)} recorded.",
        )

        add_audit_log(
            conn,
            user_id,
            "Deposit",
            money(cents),
        )


# =========================================================
# WITHDRAW MONEY
# =========================================================

def withdraw_money(
    user_id,
    cents,
    description="Cash withdrawal",
):
    if cents <= 0:
        raise ValueError(
            "Withdrawal amount must be positive."
        )

    with connect_db() as conn:
        account = conn.execute(
            """
            SELECT balance_cents, status
            FROM bank_accounts
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

        if account is None:
            raise ValueError("Bank account not found.")

        balance, status = account

        if status != "Active":
            raise ValueError("This account is not active.")

        if cents > balance:
            raise ValueError(
                "Insufficient funds. Your available balance is "
                + money(balance)
            )

        # Conditional update prevents the balance going negative.
        cursor = conn.execute(
            """
            UPDATE bank_accounts
            SET balance_cents = balance_cents - ?
            WHERE user_id = ?
              AND status = 'Active'
              AND balance_cents >= ?
            """,
            (cents, user_id, cents),
        )

        if cursor.rowcount != 1:
            raise ValueError(
                "Withdrawal could not be completed."
            )

        conn.execute(
            """
            INSERT INTO bank_transactions (
                reference, user_id, transaction_type,
                amount_cents, description,
                related_account, transaction_date
            )
            VALUES (?, ?, 'Withdrawal', ?, ?, '', ?)
            """,
            (
                create_reference(),
                user_id,
                cents,
                description,
                date.today().isoformat(),
            ),
        )

        add_notification(
            conn,
            user_id,
            f"Demo withdrawal of {money(cents)} recorded.",
        )

        add_audit_log(
            conn,
            user_id,
            "Withdrawal",
            money(cents),
        )


# =========================================================
# TRANSFER MONEY TO ANOTHER WORTHY BANK ACCOUNT
# =========================================================

def transfer_money(
    sender_id,
    recipient_account_number,
    cents,
):
    recipient_account_number = (
        recipient_account_number or ""
    ).strip()

    if cents <= 0:
        raise ValueError(
            "Transfer amount must be positive."
        )

    if not recipient_account_number.isdigit():
        raise ValueError(
            "Enter a valid recipient account number."
        )

    with connect_db() as conn:
        sender = conn.execute(
            """
            SELECT account_number, balance_cents, status
            FROM bank_accounts
            WHERE user_id = ?
            """,
            (sender_id,),
        ).fetchone()

        recipient = conn.execute(
            """
            SELECT user_id, account_number, status
            FROM bank_accounts
            WHERE account_number = ?
            """,
            (recipient_account_number,),
        ).fetchone()

        if sender is None or recipient is None:
            raise ValueError(
                "Sender or recipient account was not found."
            )

        sender_number, balance, sender_status = sender
        recipient_id, recipient_number, recipient_status = recipient

        if sender_status != "Active":
            raise ValueError("Your account is not active.")

        if recipient_status != "Active":
            raise ValueError("The recipient account is not active.")

        if sender_id == recipient_id:
            raise ValueError(
                "You cannot transfer money to your own account."
            )

        if cents > balance:
            raise ValueError(
                "Insufficient funds. Your available balance is "
                + money(balance)
            )

        # Both updates and both ledger entries run inside the
        # same SQLite transaction.
        debit = conn.execute(
            """
            UPDATE bank_accounts
            SET balance_cents = balance_cents - ?
            WHERE user_id = ?
              AND status = 'Active'
              AND balance_cents >= ?
            """,
            (cents, sender_id, cents),
        )

        if debit.rowcount != 1:
            raise ValueError(
                "Transfer could not be completed."
            )

        credit = conn.execute(
            """
            UPDATE bank_accounts
            SET balance_cents = balance_cents + ?
            WHERE user_id = ?
              AND status = 'Active'
            """,
            (cents, recipient_id),
        )

        if credit.rowcount != 1:
            raise ValueError(
                "Recipient could not be credited."
            )

        reference = create_reference()
        today = date.today().isoformat()

        conn.execute(
            """
            INSERT INTO bank_transactions (
                reference, user_id, transaction_type,
                amount_cents, description,
                related_account, transaction_date
            )
            VALUES (?, ?, 'Transfer Out', ?,
                    'Demo bank transfer', ?, ?)
            """,
            (
                reference,
                sender_id,
                cents,
                recipient_number,
                today,
            ),
        )

        conn.execute(
            """
            INSERT INTO bank_transactions (
                reference, user_id, transaction_type,
                amount_cents, description,
                related_account, transaction_date
            )
            VALUES (?, ?, 'Transfer In', ?,
                    'Demo bank transfer', ?, ?)
            """,
            (
                reference,
                recipient_id,
                cents,
                sender_number,
                today,
            ),
        )

        add_notification(
            conn,
            sender_id,
            f"Demo transfer of {money(cents)} sent.",
        )

        add_notification(
            conn,
            recipient_id,
            f"Demo transfer of {money(cents)} received.",
        )

        add_audit_log(
            conn,
            sender_id,
            "Transfer Out",
            f"{money(cents)} to {recipient_number}",
        )

        add_audit_log(
            conn,
            recipient_id,
            "Transfer In",
            f"{money(cents)} from {sender_number}",
        )


# =========================================================
# BANK TRANSACTION HISTORY
# =========================================================

def get_bank_transactions(user_id):
    with connect_db() as conn:
        return conn.execute(
            """
            SELECT reference, transaction_type, amount_cents,
                   description, related_account, transaction_date
            FROM bank_transactions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (user_id,),
        ).fetchall()


def get_notifications(user_id):
    with connect_db() as conn:
        return conn.execute(
            """
            SELECT id, message, created_date
            FROM notifications
            WHERE user_id = ? AND is_read = 0
            ORDER BY id DESC
            LIMIT 20
            """,
            (user_id,),
        ).fetchall()


def mark_notifications_read(user_id):
    with connect_db() as conn:
        conn.execute(
            """
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = ?
            """,
            (user_id,),
        )


# =========================================================
# PERSONAL FINANCE TRANSACTIONS
# =========================================================

def get_totals(user_id):
    with connect_db() as conn:
        rows = conn.execute(
            """
            SELECT kind, COALESCE(SUM(amount_cents), 0)
            FROM transactions
            WHERE user_id = ?
            GROUP BY kind
            """,
            (user_id,),
        ).fetchall()

    totals = {"Income": 0, "Expense": 0}

    for kind, amount in rows:
        totals[kind] = amount

    return totals["Income"], totals["Expense"]


def get_transactions(user_id):
    with connect_db() as conn:
        return conn.execute(
            """
            SELECT kind, amount_cents, category,
                   description, transaction_date
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (user_id,),
        ).fetchall()


def add_transaction(
    user_id,
    kind,
    cents,
    category,
    description,
):
    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO transactions (
                user_id, kind, amount_cents, category,
                description, transaction_date
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                kind,
                cents,
                category,
                description,
                date.today().isoformat(),
            ),
        )


# =========================================================
# SAVINGS GOALS
# =========================================================

def get_savings_goals(user_id):
    with connect_db() as conn:
        return conn.execute(
            """
            SELECT id, name, target_cents, saved_cents
            FROM savings_goals
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,),
        ).fetchall()


def create_savings_goal(user_id, name, target_cents):
    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO savings_goals (
                user_id, name, target_cents,
                saved_cents, created_date
            )
            VALUES (?, ?, ?, 0, ?)
            """,
            (
                user_id,
                name,
                target_cents,
                date.today().isoformat(),
            ),
        )


def add_savings_contribution(
    user_id,
    goal_id,
    amount_cents,
):
    if amount_cents <= 0:
        return False

    with connect_db() as conn:
        goal = conn.execute(
            """
            SELECT target_cents, saved_cents
            FROM savings_goals
            WHERE id = ? AND user_id = ?
            """,
            (goal_id, user_id),
        ).fetchone()

        if goal is None:
            return False

        target, saved = goal

        if saved + amount_cents > target:
            return False

        conn.execute(
            """
            UPDATE savings_goals
            SET saved_cents = saved_cents + ?
            WHERE id = ? AND user_id = ?
            """,
            (amount_cents, goal_id, user_id),
        )

    return True


# =========================================================
# MONTHLY BUDGETS
# =========================================================

def set_budget(user_id, category, month, limit_cents):
    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO budgets (
                user_id, category, month, limit_cents
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, category, month)
            DO UPDATE SET limit_cents = excluded.limit_cents
            """,
            (user_id, category, month, limit_cents),
        )


def get_budgets(user_id, month):
    with connect_db() as conn:
        limits = conn.execute(
            """
            SELECT category, limit_cents
            FROM budgets
            WHERE user_id = ? AND month = ?
            """,
            (user_id, month),
        ).fetchall()

        spent = conn.execute(
            """
            SELECT category, SUM(amount_cents)
            FROM transactions
            WHERE user_id = ?
              AND kind = 'Expense'
              AND substr(transaction_date, 1, 7) = ?
            GROUP BY category
            """,
            (user_id, month),
        ).fetchall()

    return dict(limits), dict(spent)


# =========================================================
# FLET APPLICATION
# =========================================================

def main(page: ft.Page):
    initialise_database()

    page.title = "Worthy Bank"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.bgcolor = LIGHT_BACKGROUND
    page.padding = 20
    page.scroll = ft.ScrollMode.AUTO
    page.theme = ft.Theme(color_scheme_seed=GREEN)

    current_user = {
        "id": None,
        "email": None,
    }

    def show_message(control, message, color=ERROR):
        control.value = message
        control.color = color
        page.update()

    def heading(title, subtitle=None):
        controls = [
            ft.Text(
                title,
                size=22,
                weight=ft.FontWeight.BOLD,
                color=DARK_GREEN,
            )
        ]

        if subtitle:
            controls.append(
                ft.Text(
                    subtitle,
                    size=13,
                    color=MUTED,
                )
            )

        return ft.Column(
            controls=controls,
            spacing=4,
        )

    def logout(e=None):
        current_user["id"] = None
        current_user["email"] = None
        show_auth()

    # =====================================================
    # LOGIN AND REGISTRATION
    # =====================================================

    def show_auth():
        page.controls.clear()

        email = ft.TextField(
            label="Email address",
            keyboard_type=ft.KeyboardType.EMAIL,
            autofocus=True,
        )

        password = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
        )

        status = ft.Text(size=13)
        create_mode = {"value": False}

        def submit(e):
            if create_mode["value"]:
                user_id, message = register_user(
                    email.value,
                    password.value,
                )

                if user_id is not None:
                    status.value = message
                    status.color = SUCCESS
                    create_mode["value"] = False

                    submit_button.text = "Sign in"
                    toggle_button.text = "Create an account"
                    password.value = ""
                    password.label = "Password"
                else:
                    status.value = message
                    status.color = ERROR

            else:
                user = authenticate_user(
                    email.value,
                    password.value,
                )

                if user:
                    current_user.update(user)
                    show_dashboard()
                    return

                status.value = (
                    "Email or password is incorrect, "
                    "or the account is not active."
                )
                status.color = ERROR

            page.update()

        def toggle(e):
            create_mode["value"] = not create_mode["value"]
            status.value = ""

            if create_mode["value"]:
                submit_button.text = "Create account"
                toggle_button.text = "I already have an account"
                password.label = "Password (minimum 8 characters)"
            else:
                submit_button.text = "Sign in"
                toggle_button.text = "Create an account"
                password.label = "Password"

            page.update()

        submit_button = ft.Button(
            "Sign in",
            on_click=submit,
            style=ft.ButtonStyle(
                bgcolor=GREEN,
                color="white",
            ),
        )

        toggle_button = ft.TextButton(
            "Create an account",
            on_click=toggle,
        )

        page.add(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Icon(
                            ft.Icons.ACCOUNT_BALANCE_WALLET,
                            size=52,
                            color=GREEN,
                        ),
                        heading(
                            "Worthy Bank",
                            "Your money. Your confidence.",
                        ),
                        ft.Text(
                            "Create an account or sign in to "
                            "manage your finances.",
                            color="#475467",
                        ),
                        email,
                        password,
                        submit_button,
                        toggle_button,
                        status,
                        ft.Text(
                            "This is a simulated banking application. "
                            "It does not hold or transfer real money.",
                            size=12,
                            color=MUTED,
                        ),
                    ],
                    spacing=16,
                    horizontal_alignment=(
                        ft.CrossAxisAlignment.STRETCH
                    ),
                ),
                padding=24,
                bgcolor="white",
                border_radius=16,
                width=480,
            )
        )

        page.update()

    # =====================================================
    # DASHBOARD
    # =====================================================

    def show_dashboard():
        page.controls.clear()

        user_id = current_user["id"]
        status = ft.Text(size=13)

        account_number_text = ft.Text(
            size=14,
            color="white",
        )

        account_type_text = ft.Text(
            size=12,
            color="#D7EAE5",
        )

        balance_text = ft.Text(
            size=30,
            weight=ft.FontWeight.BOLD,
            color="white",
        )

        income_text = ft.Text(size=20, color=SUCCESS)
        expense_text = ft.Text(size=20, color=ERROR)

        # Banking controls.
        deposit_amount = ft.TextField(
            label="Deposit amount (R)",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        withdraw_amount = ft.TextField(
            label="Withdrawal amount (R)",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        transfer_amount = ft.TextField(
            label="Transfer amount (R)",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        recipient_account = ft.TextField(
            label="Recipient account number",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        bank_history = ft.Column(spacing=8)
        notification_list = ft.Column(spacing=8)
        transaction_list = ft.Column(spacing=8)
        goals_list = ft.Column(spacing=8)
        budgets_list = ft.Column(spacing=8)

        # Personal finance controls.
        amount_input = ft.TextField(
            label="Amount in rand (e.g. 150.50)",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        description_input = ft.TextField(
            label="Description (optional)",
        )

        kind_input = ft.Dropdown(
            label="Transaction type",
            value="Expense",
            options=[
                ft.dropdown.Option("Income"),
                ft.dropdown.Option("Expense"),
            ],
        )

        category_input = ft.Dropdown(
            label="Category",
            value="Food",
            options=[
                ft.dropdown.Option(c)
                for c in CATEGORIES
            ],
        )

        goal_name = ft.TextField(
            label="Savings goal name",
            hint_text="e.g. Emergency fund",
        )

        goal_target = ft.TextField(
            label="Target amount (R)",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        goal_choice = ft.Dropdown(
            label="Choose savings goal",
            options=[],
        )

        goal_contribution = ft.TextField(
            label="Contribution amount (R)",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        budget_category = ft.Dropdown(
            label="Budget category",
            value="Food",
            options=[
                ft.dropdown.Option(c)
                for c in BUDGET_CATEGORIES
            ],
        )

        budget_amount = ft.TextField(
            label="Monthly budget limit (R)",
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        current_month = date.today().strftime("%Y-%m")

        # =================================================
        # REFRESH ALL DASHBOARD DATA
        # =================================================

        def refresh_dashboard():
            account = get_account(user_id)

            if account is None:
                show_message(
                    status,
                    "Could not find your bank account.",
                )
                return

            account_number, account_type, balance, account_status = account

            account_number_text.value = (
                f"Account number: {account_number}"
            )

            account_type_text.value = (
                f"{account_type} account • {account_status}"
            )

            balance_text.value = money(balance)

            income, expenses = get_totals(user_id)
            income_text.value = money(income)
            expense_text.value = money(expenses)

            # Bank transaction history.
            bank_history.controls.clear()

            for (
                reference,
                tx_type,
                cents,
                description,
                related_account,
                tx_date,
            ) in get_bank_transactions(user_id):

                is_credit = tx_type in (
                    "Deposit",
                    "Transfer In",
                )

                symbol = "+" if is_credit else "−"
                color = SUCCESS if is_credit else ERROR

                details = description or tx_type

                if related_account:
                    details += (
                        f" • Related account: {related_account}"
                    )

                bank_history.controls.append(
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Text(
                                            tx_type,
                                            weight=ft.FontWeight.BOLD,
                                            expand=True,
                                        ),
                                        ft.Text(
                                            f"{symbol}{money(cents)}",
                                            color=color,
                                            weight=ft.FontWeight.BOLD,
                                        ),
                                    ]
                                ),
                                ft.Text(
                                    f"{tx_date} • Ref: {reference}",
                                    size=11,
                                    color=MUTED,
                                ),
                                ft.Text(
                                    details,
                                    size=12,
                                ),
                            ],
                            spacing=4,
                        ),
                        padding=12,
                        bgcolor="white",
                        border_radius=10,
                    )
                )

            if not bank_history.controls:
                bank_history.controls.append(
                    ft.Text(
                        "No banking transactions yet.",
                        color=MUTED,
                    )
                )

            # Notifications.
            notification_list.controls.clear()

            notifications = get_notifications(user_id)

            for notification_id, message, created in notifications:
                notification_list.controls.append(
                    ft.Container(
                        content=ft.Text(
                            f"🔔 {message} • {created}",
                            size=13,
                        ),
                        padding=10,
                        bgcolor="white",
                        border_radius=8,
                    )
                )

            if not notifications:
                notification_list.controls.append(
                    ft.Text(
                        "You have no unread notifications.",
                        color=MUTED,
                    )
                )

            # Personal finance transactions.
            transaction_list.controls.clear()

            transactions = get_transactions(user_id)

            for kind, cents, category, description, tx_date in transactions:
                symbol = "+" if kind == "Income" else "−"
                color = SUCCESS if kind == "Income" else ERROR

                details = f"{category} • {tx_date}"

                if description:
                    details += f" • {description}"

                transaction_list.controls.append(
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Column(
                                    [
                                        ft.Text(
                                            kind,
                                            weight=ft.FontWeight.BOLD,
                                        ),
                                        ft.Text(
                                            details,
                                            size=12,
                                            color=MUTED,
                                        ),
                                    ],
                                    expand=True,
                                    spacing=4,
                                ),
                                ft.Text(
                                    f"{symbol}{money(cents)}",
                                    color=color,
                                    weight=ft.FontWeight.BOLD,
                                ),
                            ],
                            alignment=(
                                ft.MainAxisAlignment.SPACE_BETWEEN
                            ),
                        ),
                        padding=12,
                        bgcolor="white",
                        border_radius=10,
                    )
                )

            if not transactions:
                transaction_list.controls.append(
                    ft.Text(
                        "No personal finance transactions yet.",
                        color=MUTED,
                    )
                )

            # Savings goals.
            goals = get_savings_goals(user_id)
            goals_list.controls.clear()

            goal_choice.options = [
                ft.dropdown.Option(str(g[0]), g[1])
                for g in goals
            ]

            if goal_choice.value and not any(
                str(g[0]) == goal_choice.value
                for g in goals
            ):
                goal_choice.value = None

            for goal_id, name, target, saved in goals:
                progress = min(saved / target, 1.0)

                goals_list.controls.append(
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Text(
                                            name,
                                            weight=ft.FontWeight.BOLD,
                                            expand=True,
                                        ),
                                        ft.Text(f"{progress:.0%}"),
                                    ]
                                ),
                                ft.ProgressBar(
                                    value=progress,
                                    color=GREEN,
                                    bgcolor="#E4E7EC",
                                ),
                                ft.Text(
                                    f"{money(saved)} saved of "
                                    f"{money(target)}",
                                    size=13,
                                    color="#475467",
                                ),
                            ],
                            spacing=6,
                        ),
                        padding=12,
                        bgcolor="white",
                        border_radius=10,
                    )
                )

            if not goals:
                goals_list.controls.append(
                    ft.Text(
                        "No savings goals yet.",
                        color=MUTED,
                    )
                )

            # Monthly budgets.
            limits, spent = get_budgets(
                user_id,
                current_month,
            )

            budgets_list.controls.clear()

            if not limits:
                budgets_list.controls.append(
                    ft.Text(
                        "No budgets set for this month.",
                        color=MUTED,
                    )
                )

            for category, limit in limits.items():
                used = spent.get(category, 0)
                remaining = limit - used
                progress = min(used / limit, 1.0)

                if remaining < 0:
                    note = (
                        f"Over budget by {money(-remaining)}"
                    )
                    note_color = ERROR
                else:
                    note = f"{money(remaining)} remaining"
                    note_color = SUCCESS

                budgets_list.controls.append(
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Text(
                                            category,
                                            weight=ft.FontWeight.BOLD,
                                            expand=True,
                                        ),
                                        ft.Text(
                                            f"Limit {money(limit)}",
                                            size=12,
                                        ),
                                    ]
                                ),
                                ft.ProgressBar(
                                    value=progress,
                                    color=(
                                        ERROR if used > limit
                                        else GREEN
                                    ),
                                    bgcolor="#E4E7EC",
                                ),
                                ft.Row(
                                    [
                                        ft.Text(
                                            f"Spent {money(used)}",
                                            size=12,
                                        ),
                                        ft.Text(
                                            note,
                                            color=note_color,
                                            size=12,
                                        ),
                                    ]
                                ),
                            ],
                            spacing=6,
                        ),
                        padding=12,
                        bgcolor="white",
                        border_radius=10,
                    )
                )

            page.update()

        # =================================================
        # DEPOSIT
        # =================================================

        def handle_deposit(e):
            try:
                cents = parse_cents(deposit_amount.value)

                deposit_money(
                    user_id,
                    cents,
                    "Customer demo deposit",
                )

                deposit_amount.value = ""

                show_message(
                    status,
                    f"Deposit successful: {money(cents)}",
                    SUCCESS,
                )

                refresh_dashboard()

            except ValueError as exc:
                show_message(status, str(exc))

            except sqlite3.Error:
                show_message(
                    status,
                    "Deposit failed because of a database error.",
                )

        # =================================================
        # WITHDRAWAL
        # =================================================

        def handle_withdrawal(e):
            try:
                cents = parse_cents(withdraw_amount.value)

                withdraw_money(
                    user_id,
                    cents,
                    "Customer demo withdrawal",
                )

                withdraw_amount.value = ""

                show_message(
                    status,
                    f"Withdrawal successful: {money(cents)}",
                    SUCCESS,
                )

                refresh_dashboard()

            except ValueError as exc:
                show_message(status, str(exc))

            except sqlite3.Error:
                show_message(
                    status,
                    "Withdrawal failed because of a database error.",
                )

        # =================================================
        # TRANSFER
        # =================================================

        def handle_transfer(e):
            try:
                cents = parse_cents(transfer_amount.value)

                recipient = (
                    recipient_account.value or ""
                ).strip()

                transfer_money(
                    user_id,
                    recipient,
                    cents,
                )

                transfer_amount.value = ""
                recipient_account.value = ""

                show_message(
                    status,
                    f"Transfer successful: {money(cents)}",
                    SUCCESS,
                )

                refresh_dashboard()

            except ValueError as exc:
                show_message(status, str(exc))

            except sqlite3.Error:
                show_message(
                    status,
                    "Transfer failed because of a database error.",
                )

        # =================================================
        # MARK NOTIFICATIONS AS READ
        # =================================================

        def clear_notifications(e):
            mark_notifications_read(user_id)

            show_message(
                status,
                "Notifications marked as read.",
                SUCCESS,
            )

            refresh_dashboard()

        # =================================================
        # SAVE PERSONAL FINANCE TRANSACTION
        # =================================================

        def save_transaction(e):
            try:
                cents = parse_cents(amount_input.value)
                kind = kind_input.value
                category = category_input.value

                description = (
                    description_input.value or ""
                ).strip()

                if kind not in ("Income", "Expense"):
                    raise ValueError(
                        "Choose a transaction type."
                    )

                if category not in CATEGORIES:
                    raise ValueError(
                        "Choose a valid category."
                    )

                if len(description) > 120:
                    raise ValueError(
                        "Description must be 120 characters "
                        "or less."
                    )

                add_transaction(
                    user_id,
                    kind,
                    cents,
                    category,
                    description,
                )

                amount_input.value = ""
                description_input.value = ""

                show_message(
                    status,
                    "Personal finance transaction saved.",
                    SUCCESS,
                )

                refresh_dashboard()

            except ValueError as exc:
                show_message(status, str(exc))

            except sqlite3.Error:
                show_message(
                    status,
                    "Could not save the transaction.",
                )

        # =================================================
        # CREATE SAVINGS GOAL
        # =================================================

        def save_goal(e):
            name = (goal_name.value or "").strip()

            if not name or len(name) > 80:
                show_message(
                    status,
                    "Enter a goal name of 1–80 characters.",
                )
                return

            try:
                target = parse_cents(goal_target.value)

                create_savings_goal(
                    user_id,
                    name,
                    target,
                )

                goal_name.value = ""
                goal_target.value = ""

                show_message(
                    status,
                    "Savings goal created successfully.",
                    SUCCESS,
                )

                refresh_dashboard()

            except ValueError:
                show_message(
                    status,
                    "Enter a valid positive target amount.",
                )

            except sqlite3.Error:
                show_message(
                    status,
                    "Could not save the savings goal.",
                )

        # =================================================
        # ADD SAVINGS CONTRIBUTION
        # =================================================

        def contribute(e):
            try:
                goal_id = int(goal_choice.value or "")
                amount = parse_cents(
                    goal_contribution.value
                )

            except (ValueError, TypeError):
                show_message(
                    status,
                    "Choose a savings goal and enter a valid amount.",
                )
                return

            if add_savings_contribution(
                user_id,
                goal_id,
                amount,
            ):
                goal_contribution.value = ""

                show_message(
                    status,
                    "Savings contribution recorded.",
                    SUCCESS,
                )

                refresh_dashboard()

            else:
                show_message(
                    status,
                    "Contribution not added. Check the goal "
                    "and ensure the target will not be exceeded.",
                )

        # =================================================
        # SAVE MONTHLY BUDGET
        # =================================================

        def save_budget(e):
            category = budget_category.value

            if category not in BUDGET_CATEGORIES:
                show_message(
                    status,
                    "Choose a valid budget category.",
                )
                return

            try:
                limit = parse_cents(budget_amount.value)

                set_budget(
                    user_id,
                    category,
                    current_month,
                    limit,
                )

                budget_amount.value = ""

                show_message(
                    status,
                    f"{category} budget saved for {current_month}.",
                    SUCCESS,
                )

                refresh_dashboard()

            except ValueError:
                show_message(
                    status,
                    "Enter a valid positive monthly limit.",
                )

            except sqlite3.Error:
                show_message(
                    status,
                    "Could not save the budget.",
                )

        # =================================================
        # MONEY CONFIDENCE COACH
        # =================================================

        coach_output = ft.Text(
            "",
            color="#344054",
            selectable=True,
        )

        def coach_text():
            income, expenses = get_totals(user_id)

            limits, spent = get_budgets(
                user_id,
                current_month,
            )

            goals = get_savings_goals(user_id)

            account = get_account(user_id)
            bank_balance = account[2] if account else 0

            messages = [
                f"Your bank balance is "
                f"{money(bank_balance)}."
            ]

            if income == 0 and expenses == 0:
                messages.append(
                    "Start by recording your income and expenses "
                    "to understand your money patterns."
                )
            else:
                messages.append(
                    f"You recorded {money(income)} in income and "
                    f"{money(expenses)} in expenses in your "
                    f"personal finance tracker."
                )

                if expenses > income:
                    messages.append(
                        "Your recorded expenses are higher than "
                        "your recorded income. Review flexible "
                        "spending and upcoming bills."
                    )
                elif income > expenses:
                    messages.append(
                        "Your recorded income is higher than "
                        "expenses. Consider a realistic savings "
                        "plan after covering essential needs."
                    )
                else:
                    messages.append(
                        "Your recorded income and expenses are "
                        "equal. Plan ahead for upcoming bills."
                    )

            over_budget = [
                (category, used - limits[category])
                for category, used in spent.items()
                if category in limits
                and used > limits[category]
            ]

            if over_budget:
                category, amount = max(
                    over_budget,
                    key=lambda item: item[1],
                )

                messages.append(
                    f"Your {category.lower()} spending is over "
                    f"its monthly budget by {money(amount)}."
                )

            if goals:
                closest = max(
                    goals,
                    key=lambda goal: goal[3] / goal[2],
                )

                progress = min(
                    closest[3] / closest[2],
                    1.0,
                )

                messages.append(
                    f'Your goal "{closest[1]}" is '
                    f"{progress:.0%} funded."
                )
            else:
                messages.append(
                    "Try creating a savings goal for an emergency "
                    "fund, education, or another priority."
                )

            messages.append(
                "Remember: your banking balance and personal "
                "finance tracker are separate. Recording an income "
                "entry does not deposit money into your bank account."
            )

            return "\n\n".join(messages)

        def refresh_coach(e=None):
            coach_output.value = coach_text()
            page.update()

        # =================================================
        # DASHBOARD LAYOUT
        # =================================================

        page.add(
            ft.Column(
                [
                    # Header.
                    ft.Row(
                        [
                            ft.Icon(
                                ft.Icons.ACCOUNT_BALANCE_WALLET,
                                color=GREEN,
                                size=34,
                            ),
                            ft.Column(
                                [
                                    ft.Text(
                                        "Worthy Bank",
                                        size=26,
                                        weight=ft.FontWeight.BOLD,
                                        color=DARK_GREEN,
                                    ),
                                    ft.Text(
                                        f"{current_user['email']}",
                                        size=12,
                                        color=MUTED,
                                    ),
                                ],
                                spacing=2,
                                expand=True,
                            ),
                            ft.TextButton(
                                "Log out",
                                on_click=logout,
                            ),
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),

                    # Bank account card.
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Text(
                                    "AVAILABLE BALANCE",
                                    color="white",
                                    size=12,
                                ),
                                balance_text,
                                account_number_text,
                                account_type_text,
                                ft.Text(
                                    "Account only — no real money.",
                                    color="#D7EAE5",
                                    size=12,
                                ),
                            ],
                            spacing=8,
                        ),
                        bgcolor=GREEN,
                        padding=22,
                        border_radius=16,
                    ),

                    # Income and expenses in the personal tracker.
                    heading(
                        "Personal finance overview",
                        "These figures are separate from your bank balance.",
                    ),

                    ft.Row(
                        [
                            ft.Container(
                                content=ft.Column(
                                    [
                                        ft.Text("Recorded income"),
                                        income_text,
                                    ],
                                    spacing=8,
                                ),
                                bgcolor="white",
                                padding=14,
                                border_radius=12,
                                expand=True,
                            ),
                            ft.Container(
                                content=ft.Column(
                                    [
                                        ft.Text("Recorded expenses"),
                                        expense_text,
                                    ],
                                    spacing=8,
                                ),
                                bgcolor="white",
                                padding=14,
                                border_radius=12,
                                expand=True,
                            ),
                        ]
                    ),

                    ft.Divider(),

                    # Deposits.
                    heading(
                        "Deposit money",
                        "Add simulated funds to your account.",
                    ),

                    deposit_amount,

                    ft.Button(
                        "Deposit money",
                        icon=ft.Icons.ADD_CIRCLE_OUTLINE,
                        on_click=handle_deposit,
                        style=ft.ButtonStyle(
                            bgcolor=GREEN,
                            color="white",
                        ),
                    ),

                    # Withdrawals.
                    heading(
                        "Withdraw money",
                        "Withdrawals cannot exceed your available balance.",
                    ),

                    withdraw_amount,

                    ft.Button(
                        "Withdraw money",
                        icon=ft.Icons.REMOVE_CIRCLE_OUTLINE,
                        on_click=handle_withdrawal,
                        style=ft.ButtonStyle(
                            bgcolor=GREEN,
                            color="white",
                        ),
                    ),

                    # Transfers.
                    heading(
                        "Transfer money",
                        "Send simulated funds to another Worthy Bank account.",
                    ),

                    recipient_account,
                    transfer_amount,

                    ft.Button(
                        "Transfer money",
                        icon=ft.Icons.SWAP_HORIZ,
                        on_click=handle_transfer,
                        style=ft.ButtonStyle(
                            bgcolor=GREEN,
                            color="white",
                        ),
                    ),

                    status,

                    ft.Divider(),

                    # Banking history.
                    heading(
                        "Bank transaction history",
                        "Deposits, withdrawals and transfers.",
                    ),

                    bank_history,

                    ft.Divider(),

                    # Notifications.
                    heading("Notifications"),
                    notification_list,

                    ft.TextButton(
                        "Mark notifications as read",
                        on_click=clear_notifications,
                    ),

                    ft.Divider(),

                    # Personal finance tracker.
                    heading(
                        "Record income or expense",
                        "This tracker does not change your bank balance.",
                    ),

                    kind_input,
                    amount_input,
                    category_input,
                    description_input,

                    ft.Button(
                        "Save personal finance transaction",
                        on_click=save_transaction,
                    ),

                    heading("Recent personal finance entries"),
                    transaction_list,

                    ft.Divider(),

                    # Savings goals.
                    heading(
                        "Savings goals",
                        "Track your savings targets.",
                    ),

                    goal_name,
                    goal_target,

                    ft.Button(
                        "Create savings goal",
                        on_click=save_goal,
                    ),

                    goals_list,
                    goal_choice,
                    goal_contribution,

                    ft.Button(
                        "Add savings contribution",
                        on_click=contribute,
                    ),

                    ft.Divider(),

                    # Budgets.
                    heading(
                        "Monthly budget planner",
                        f"Budget month: {current_month}",
                    ),

                    budget_category,
                    budget_amount,

                    ft.Button(
                        "Save monthly budget",
                        on_click=save_budget,
                    ),

                    budgets_list,

                    ft.Divider(),

                    # Coach.
                    heading(
                        "Money Confidence Coach",
                        "Supportive suggestions based on your recorded data.",
                    ),

                    ft.Container(
                        content=coach_output,
                        padding=16,
                        bgcolor="white",
                        border_radius=12,
                    ),

                    ft.TextButton(
                        "Refresh coach advice",
                        on_click=refresh_coach,
                    ),

                    ft.Text(
                        "Worthy Bank is a local banking demonstration. "
                        "It does not connect to real banking systems, "
                        "ATMs, payment networks or real bank accounts.",
                        size=12,
                        color=MUTED,
                    ),
                ],
                spacing=14,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            )
        )

        refresh_coach()
        refresh_dashboard()
        page.update()

    show_auth()


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    initialise_database()
    ft.run(main)

