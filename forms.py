from __future__ import annotations

import json
import math
import re
from typing import Any

from flask_wtf import FlaskForm
from wtforms import (
    DateField,
    DecimalField,
    HiddenField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import (
    DataRequired,
    EqualTo,
    Length,
    NumberRange,
    Optional,
    Regexp,
    ValidationError,
)

STATUSES = ["Pending", "In Progress", "Ready", "Delivered", "Cancelled"]
PAYMENT_STATUSES = ["Unpaid", "Partially Paid", "Paid"]
MAX_CUSTOMER_NAME_LENGTH = 100
MAX_ITEM_NAME_LENGTH = 100
MAX_NOTES_LENGTH = 1000
MAX_ORDER_ITEMS = 50
MAX_QUANTITY = 10000
MAX_MONEY = 1_000_000_000
USERNAME_PATTERN = r"^[A-Za-z0-9_.-]+$"
PHONE_PATTERN = r"^[0-9+().\-\s]{7,20}$"
PASSWORD_MIN_LENGTH = 8


def validate_password_strength(value: str) -> str | None:
    if len(value) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
    if not re.search(r"[A-Z]", value):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", value):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", value):
        return "Password must include at least one number."
    if not re.search(r"[^\w\s]", value):
        return "Password must include at least one special character."
    return None


def parse_money(value: Any, field_name: str, *, allow_zero: bool = True) -> tuple[float | None, str | None]:
    try:
        amount = float(value if value not in (None, "") else 0)
    except (TypeError, ValueError):
        return None, f"{field_name} must be a valid number."

    if not math.isfinite(amount):
        return None, f"{field_name} must be a valid number."
    if amount < 0:
        return None, f"{field_name} cannot be negative."
    if not allow_zero and amount <= 0:
        return None, f"{field_name} must be greater than zero."
    if amount > MAX_MONEY:
        return None, f"{field_name} is too large."
    return round(amount, 2), None


def parse_quantity(value: Any, field_name: str) -> tuple[int | None, str | None]:
    try:
        quantity = int(value)
    except (TypeError, ValueError):
        return None, f"{field_name} must be a whole number."

    if quantity <= 0:
        return None, f"{field_name} must be greater than zero."
    if quantity > MAX_QUANTITY:
        return None, f"{field_name} is too large."
    return quantity, None


def validate_order_items(items_raw: str) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    try:
        items = json.loads(items_raw)
    except json.JSONDecodeError:
        return [], ["Order items are invalid."]

    if not isinstance(items, list):
        return [], ["Order items are invalid."]
    if len(items) > MAX_ORDER_ITEMS:
        return [], [f"Orders can have at most {MAX_ORDER_ITEMS} items."]

    clean_items: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            errors.append(f"Item {index} is invalid.")
            continue

        item_name = str(item.get("item_name", "")).strip()
        quantity_raw = item.get("quantity", "")
        unit_price_raw = item.get("unit_price", "")
        if not item_name and unit_price_raw in ("", 0, "0", None):
            continue

        if not item_name:
            errors.append(f"Item {index} name is required.")
            continue
        if len(item_name) > MAX_ITEM_NAME_LENGTH:
            errors.append(f"Item {index} name is too long.")
            continue

        quantity, quantity_error = parse_quantity(quantity_raw, f"Item {index} quantity")
        unit_price, unit_price_error = parse_money(
            unit_price_raw, f"Item {index} unit price", allow_zero=False
        )
        if quantity_error:
            errors.append(quantity_error)
        if unit_price_error:
            errors.append(unit_price_error)
        if quantity_error or unit_price_error:
            continue

        total = round(quantity * unit_price, 2)
        if total > MAX_MONEY:
            errors.append(f"Item {index} total is too large.")
            continue

        clean_items.append(
            {
                "item_name": item_name,
                "quantity": quantity,
                "unit_price": unit_price,
                "total": total,
            }
        )

    if not clean_items:
        errors.append("Please add at least one valid item.")
    return clean_items, errors


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=30)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30),
            Regexp(
                USERNAME_PATTERN,
                message="Use only letters, numbers, dots, underscores, or hyphens.",
            ),
        ],
    )
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Register")

    def validate_password(self, field: PasswordField) -> None:
        error = validate_password_strength(field.data or "")
        if error:
            raise ValidationError(error)


class AccountForm(FlaskForm):
    form_type = HiddenField(default="account")
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30),
            Regexp(
                USERNAME_PATTERN,
                message="Use only letters, numbers, dots, underscores, or hyphens.",
            ),
        ],
    )
    submit_account = SubmitField("Save Username")


class PasswordForm(FlaskForm):
    form_type = HiddenField(default="password")
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(max=128)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="New password and confirmation do not match."),
        ],
    )
    submit_password = SubmitField("Update Password")

    def validate_new_password(self, field: PasswordField) -> None:
        error = validate_password_strength(field.data or "")
        if error:
            raise ValidationError(error)


class OrderForm(FlaskForm):
    order_id = HiddenField()
    customer_name = StringField(
        "Customer Name",
        validators=[DataRequired(), Length(max=MAX_CUSTOMER_NAME_LENGTH)],
    )
    phone_number = StringField(
        "Phone Number",
        validators=[
            DataRequired(),
            Length(min=7, max=20),
            Regexp(PHONE_PATTERN, message="Phone number format is invalid."),
        ],
    )
    order_date = DateField("Order Date", validators=[DataRequired()], format="%Y-%m-%d")
    status = SelectField(
        "Status",
        choices=[(status, status) for status in STATUSES],
        validators=[DataRequired()],
    )
    payment_status = SelectField(
        "Payment Status",
        choices=[(status, status) for status in PAYMENT_STATUSES],
        validators=[DataRequired()],
    )
    deposit = DecimalField(
        "Deposit",
        places=2,
        default=0,
        validators=[Optional(), NumberRange(min=0, max=MAX_MONEY)],
    )
    notes = TextAreaField("Notes", validators=[Optional(), Length(max=MAX_NOTES_LENGTH)])
    items_json = HiddenField("Items", validators=[DataRequired()])

    clean_items: list[dict[str, Any]]

    def validate_items_json(self, field: HiddenField) -> None:
        clean_items, errors = validate_order_items(field.data or "[]")
        if errors:
            raise ValidationError("; ".join(errors[:5]))
        self.clean_items = clean_items


class DeleteForm(FlaskForm):
    pass


class LogoutForm(FlaskForm):
    pass
