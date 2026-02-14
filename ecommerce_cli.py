"""
Project #1:
E-Commerce CLI Simulation - Part E (System Development)

This script simulate and e-commerce system using in-memory data structures.
It demonstrates the logical design from Parts A-C:

Core Concepts Implemented:
- User authentication with 5-attempt lockout
- Role-Based Access Control (RBAC)
- Product filtering and search logic
- Cart + checkout workflow
- Discount calculation with stacking and cap rules
- Payment validation and fraud flagging
- Seller and Admin privilege separation

IMPORTANT:
This is a simulation, there is no real database, encryption, or persistent storage used.
Passwords are stored in plaintext for demonstration only.

Created By: Josh A
Date: 2026-02-12
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime as dt
from typing import Dict, List, Optional, Tuple



#------------------------#
#   ASCII + UI Helpers   #
#------------------------#


BANNER = r"""

$$$$$$$$\       $$$$$$\                                                                                      
$$  _____|     $$  __$$\                                                                                     
$$ |           $$ /  \__| $$$$$$\  $$$$$$\$$$$\  $$$$$$\$$$$\   $$$$$$\   $$$$$$\   $$$$$$$\  $$$$$$\        
$$$$$\ $$$$$$\ $$ |      $$  __$$\ $$  _$$  _$$\ $$  _$$  _$$\ $$  __$$\ $$  __$$\ $$  _____|$$  __$$\       
$$  __|\______|$$ |      $$ /  $$ |$$ / $$ / $$ |$$ / $$ / $$ |$$$$$$$$ |$$ |  \__|$$ /      $$$$$$$$ |      
$$ |           $$ |  $$\ $$ |  $$ |$$ | $$ | $$ |$$ | $$ | $$ |$$   ____|$$ |      $$ |      $$   ____|      
$$$$$$$$\      \$$$$$$  |\$$$$$$  |$$ | $$ | $$ |$$ | $$ | $$ |\$$$$$$$\ $$ |      \$$$$$$$\ \$$$$$$$\       
\________|      \______/  \______/ \__| \__| \__|\__| \__| \__| \_______|\__|       \_______| \_______|      
                                                                                                             
                                                                                                             
                                                                                                             
                                     $$$$$$\  $$\       $$$$$$\                                              
                                    $$  __$$\ $$ |      \_$$  _|                                             
                                    $$ /  \__|$$ |        $$ |                                               
                                    $$ |      $$ |        $$ |                                               
                                    $$ |      $$ |        $$ |                                               
                                    $$ |  $$\ $$ |        $$ |                                               
                                    \$$$$$$  |$$$$$$$$\ $$$$$$\                                              
                                     \______/ \________|\______|                                             
                                                                                                                                                                                                                      

"""


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause(msg: str = "Press Enter to continue...") -> None:
    input(msg)


def hr() -> None:
    print("-" * 72)


def money(x: float) -> str:
    return f"${x:,.2f}"


def safe_int(prompt: str, min_v: int, max_v: int) -> int:
    while True:
        s = input(prompt).strip()
        if s.isdigit():
            v = int(s)
            if min_v <= v <= max_v:
                return v
        print(f"Please enter a number between {min_v} and {max_v}.")


def safe_float(prompt: str, min_value: float, max_value: float) -> float:
    while True:
        s = input(prompt).strip()
        try:
            v = float(s)
            if min_value <= v <= max_value:
                return v
        except ValueError:
            pass
        print(f"Please enter a value between {min_value} and {max_value}.")


#-----------------------------#
#   Data models (in-memory)   #
#-----------------------------#

ROLE_BUYER = "buyer"
ROLE_SELLER = "seller"
ROLE_ADMIN = "admin"

PAYMENT_CREDIT = "credit"
PAYMENT_DEBIT = "debit"
PAYMENT_PAYPAL = "paypal"

ALLOWED_PAYMENT_METHODS = {PAYMENT_CREDIT, PAYMENT_DEBIT, PAYMENT_PAYPAL}


@dataclass
class User:
    username: str
    password: str   # for simulation only - Real Systems: Hash + Salt
    role: str
    locked: bool = False
    failed_attempts: int = 0
    created_at: dt = field(default_factory=dt.utcnow)


@dataclass
class Product:
    sku: str
    name: str
    price: float
    in_stock: int
    trending: bool = False
    on_sale: bool = False
    seller: str = "system"


@dataclass
class Order:
    order_id: str
    buyer: str
    items: List[Tuple[str, int]]    # (sku, qty)
    subtotal: float
    discount: float
    total: float
    payment_method: str
    fraud_flagged: bool
    created_at: dt = field(default_factory=dt.utcnow)



#----------------#
#   "Database"   #
#----------------#

USERS: Dict[str, User] = {
    "josh": User("josh", "buyer123", ROLE_BUYER),
    "jordan": User("jordan", "seller123", ROLE_SELLER),
    "jerome": User("jerome", "admin123", ROLE_ADMIN)
}

PRODUCTS: Dict[str, Product] = {
    "SKU1001": Product("SKU1001", "USB-C Cable (1m)", 12.99, 30, trending=True, on_sale=True, seller="jordan"),
    "SKU1002": Product("SKU1002", "Lightning Cable (2m)", 29.99, 0, trending=True, on_sale=False, seller="jordan"),
    "SKU1003": Product("SKU1003", "Mechanical Keyboard", 109.99, 12, trending=True, on_sale=False, seller="jordan"),
    "SKU1004": Product("SKU1004", "Noise-Cancelling Headphones", 299.99, 10, trending=False, on_sale=False, seller="jordan"),
    "SKU1005": Product("SKU1005", "Apple Pencil Gen2", 199.99, 0, trending=True, on_sale=True, seller="jordan"),
    "SKU1006": Product("SKU1006", "Laptop Stand", 34.95, 20, trending=False, on_sale=False, seller="jordan"),
    "SKU1007": Product("SKU1007", "(16x4) 64GB DDR5 RAM", 1299.99, 2, trending=True, on_sale=False, seller="jordan"),
}

ORDERS: List[Order] = []    # in-memory history



#-------------------------------------#
#   Logic Helpers (Parts A-C Logic)   #
#-------------------------------------#


def is_first_order(username: str) -> bool:
        return not any(o.buyer == username for o in ORDERS)


def validate_login(username: str, password: str) -> Tuple[bool, str]:
    user = USERS.get(username)
    if not user:
        return False, "User not found"
    if user.locked:
        return False, "Account is locked. Contact admin."
    
    if password == user.password:
        user.failed_attempts = 0
        return True, "Login Successful."
    else:
        user.failed_attempts += 1
        remaining = max(0, 5 - user.failed_attempts)
        if user.failed_attempts >= 5:
            user.locked = True
            return False, "Too many failed attempts. Account locked."
        return False, f"Invalid password. Attempts remaining {remaining}"


def can_access_admin(user: User) -> bool:
    return user.role == ROLE_ADMIN and not user.locked


def can_access_seller_tools(user: User) -> bool:
    return user.role in (ROLE_SELLER, ROLE_ADMIN) and not user.locked


def search_products(keyword: str = "", max_price: Optional[float] = None,
                    trending_only: bool = False, on_sale_only: bool = False) -> List[Product]:
    kw = keyword.lower().strip()
    results = []
    for product in PRODUCTS.values():
        if product.in_stock <= 0:
            continue
        if kw and kw not in product.name.lower() and kw not in product.sku.lower():
            continue
        if max_price is not None and product.price > max_price:
            continue
        if trending_only and not product.trending:
            continue
        if on_sale_only and not product.on_sale:
            continue
        results.append(product)
    results.sort(key=lambda x: (x.on_sale, x.trending, -x.price), reverse=True)
    return results


def compute_discount(subtotal: float, username: str, coupon_code: str) -> tuple[float, str | None]:
    """
    Example discount rules:

    - First order: 10% off subtotal
    - Coupon "SAVE10": $10 off
    - Coupon "SAVE20": 20% off subtotal (stacking-allowed, but capped)
    - Discount cap: cannot exceed 30% of subtotal
    
    """

    discount = 0.0
    lines: list[str] = []

    # First order discount
    if is_first_order(username):
        d = 0.10 * subtotal
        discount += d
        lines.append(f"First-order discount (10%): -{money(d)}")

    # Coupon logic
    code = coupon_code.strip().upper()
    if code == "":
        pass
    elif code == "SAVE10":
        d = 10.0
        discount += d
        lines.append(f"Coupon {code}: -{money(d)}")
    elif code == "SAVE20":
        d = 0.20 * subtotal
        discount += d
        lines.append(f"Coupon {code} (20%): -{money(d)}")
    else:
        lines.append("Invalid coupon code entered. (First-order discount may still apply.)")

    # Cap at 30% of subtotal
    cap = 0.30 * subtotal
    if discount > cap:
        lines.append(f"Discount cap applied (max 30%): adjusted to -{money(cap)}")
        discount = cap

    # Clamp to [0, subtotal]
    discount = max(0.0, min(discount, subtotal))
    return discount, lines


def validate_payment(method: str, total: float) -> Tuple[bool, str]:
    m = method.strip().lower()
    if m not in ALLOWED_PAYMENT_METHODS:
        return False, f"Payment method '{method}' not supported."
    if total <= 0:
        return False, "Total must be greater than $0.00."
    return True, "Payment accepted {simulationAPICall}."

def fraud_check(username: str, total: float, payment_method: str) -> bool:
    """
    Simple rules:
    - Flag if total > $500 using debit
    - Flag if 3+ orders in last minute (spam/bot behavior prevention)

    """
    now = dt.utcnow()
    last_minute = [o for o in ORDERS if o.buyer == username and (now - o.created_at).total_seconds() <= 60]
    if len(last_minute) >= 3:
        return True
    if total > 500 and payment_method == PAYMENT_DEBIT:
        return True
    return False



#---------------------#
#   CLI Application   #
#---------------------#


@dataclass
class Session:
    user: User
    cart: Dict[str, int] = field(default_factory=dict)  #  sku -> qty


def login_screen() -> Optional[Session]:
    clear_screen()
    print(BANNER)
    hr()
    print("LOGIN")
    hr()
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    ok, msg = validate_login(username, password)
    print(msg)
    if not ok:
        pause()
        return None
    return Session(user=USERS[username])


def main_menu(sess: Session) -> None:
    while True:
        clear_screen()
        print(BANNER)
        hr()
        print(f"Logged in as: {sess.user.username} Role: {sess.user.role}")
        hr()

        options = [
            "Browse products",
            "View cart",
            "Checkout",
            "My order history",
        ]

        if can_access_seller_tools(sess.user):
            options.append("Seller tools")
        if can_access_admin(sess.user):
            options.append("Admin tools")
        options.append("Logout")

        for i, opt in enumerate(options, 1):
            print(f"{i}) {opt}")
        
        choice = safe_int("\nSelect: ", 1, len(options))
        selected = options[choice - 1]

        if selected == "Browse products":
            browse_products(sess)
        elif selected == "View cart":
            view_cart(sess)
        elif selected == "Checkout":
            checkout(sess)
        elif selected == "My order history":
            show_order_history(sess.user.username)
        elif selected == "Seller tools":
            seller_tools(sess)
        elif selected == "Admin tools":
            admin_tools(sess)
        elif selected == "Logout":
            print("Logging out...")
            time.sleep(0.8)
            return

def browse_products(sess: Session) -> None:
    while True:
        clear_screen
        print("PRODUCT BROWSER")
        hr()
        kw = input("Keyword (or blank): ").strip()
        max_price_str = input("Max price (or blank):").strip()
        trending_only = input("Trending only? (y/N): ").strip().lower() == "y"
        sale_only = input("On sale only? (y/N): ").strip().lower() == "y"
        max_price = None
        
        if max_price_str:
            try:
                max_price = float(max_price_str)

            except ValueError:
                print("Invalid price; ignoring.")
                max_price = None
        
        results = search_products(kw, max_price, trending_only, sale_only)
        clear_screen()
        print("RESULTS")
        hr()
        if not results:
            print("No products found.")
            pause()
            return

        for idx, product in enumerate(results, 1):
            tags = []
            if product.trending: tags.append("TRENDING")
            if product.on_sale: tags.append("SALE")
            tag_str = f" [{' '.join(tags)}]" if tags else ""
            print(f"{idx}) {product.sku} - {product.name}{tag_str}")
            print(f"    Price: {money(product.price)} | Stock: {product.in_stock} | Seller: {product.seller.upper()}\n")
        
        print("\nOptions:")
        print("1) Add item to cart")
        print("2) New search")
        print("3) Back to main menu")
        c = safe_int("Select: ", 1, 3)

        if c == 1:
            pick = safe_int("Which item #? ", 1, len(results))
            product = results[pick - 1]
            qty = safe_int("Qty: ", 1, min(99, product.in_stock))
            sess.cart[product.sku] = sess.cart.get(product.sku, 0) + qty
            print(f"Added {qty} x {product.name} to cart.")
            pause()
        elif c == 2:
            continue
        else:
            return

def view_cart(sess: Session) -> None:
    clear_screen()
    print("YOUR CART")
    hr()
    if not sess.cart:
        print("(empty)")
        pause()
        return

    subtotal = 0.0
    lines = []
    for sku, qty in sess.cart.items():
        product = PRODUCTS.get(sku)
        
        if not product:
            continue
        line_total = product.price * qty
        subtotal += line_total
        lines.append((sku, product.name, qty, product.price, line_total))

        for sku, name, qty, price, line_total in lines:
            print(f"{sku}  {name}")
            print(f"    Qty: {qty} Unit: {money(price)} Line: {money(line_total)}")
        
        hr()
        print(f"Subtotal: {money(subtotal)}")
        hr()
        print("1) Remove item")
        print("2) Clear cart")
        print("3) Back")
        c = safe_int("Select: ", 1, 3)

        if c == 1:
            sku = input("Enter SKU to remove: ").strip().upper()
            if sku in sess.cart:
                del sess.cart[sku]
                print("Removed {sku} from cart.")
            else:
                print("{sku} not in cart.")
            pause()
        elif c == 2:
            sess.cart.clear()
            print("Cart cleared.")
            pause()
        else:
            return
    

def checkout(sess: Session) -> None:
    clear_screen()
    print("CHECKOUT")
    hr()

    if not sess.cart:
        print("Cart is empty.")
        pause()
        return

    # 1) Validate cart items and stock, compute subtotal
    subtotal = 0.0
    for sku, qty in sess.cart.items():
        p = PRODUCTS.get(sku)
        if not p:
            print(f"Missing product: {sku}. Remove it from cart.")
            pause()
            return
        if qty <= 0:
            print(f"Invalid quantity for {sku}.")
            pause()
            return
        if qty > p.in_stock:
            print(f"Not enough stock for {p.name}. Requested {qty}, available {p.in_stock}.")
            pause()
            return
        subtotal += p.price * qty

    print(f"Subtotal: {money(subtotal)}")

    # 2) Coupon + discount (now returns (discount, coupon_msg))
    coupon = input("Coupon code (optional): ").strip()
    discount, discount_lines = compute_discount(subtotal, sess.user.username, coupon)
    total = max(0.0, subtotal - discount)

    if discount_lines:
        print("\nDiscount details:")
        for line in discount_lines:
            print(f"  - {line}")

    print(f"\nDiscount total: -{money(discount)}")
    print(f"Total:          {money(total)}")
    hr()

    # 3) Payment method + validation
    method = input("Payment method (credit/debit/paypal): ").strip().lower()
    ok, msg = validate_payment(method, total)
    if not ok:
        print(msg)
        pause()
        return

    # 4) Fraud check (simulation)
    flagged = fraud_check(sess.user.username, total, method)
    if flagged:
        print("Fraud check: FLAGGED (simulatedAPICall). Order will be marked for review.")

    # 5) Commit inventory + record order (only after validations succeed)
    order_id = f"ORD{len(ORDERS)+1:05d}"

    for sku, qty in sess.cart.items():
        PRODUCTS[sku].in_stock -= qty

    ORDERS.append(Order(
        order_id=order_id,
        buyer=sess.user.username,
        items=list(sess.cart.items()),
        subtotal=subtotal,
        discount=discount,
        total=total,
        payment_method=method,
        fraud_flagged=flagged
    ))

    # Clear cart after successful checkout
    sess.cart.clear()

    # 6) Confirmation screen
    clear_screen()
    print(r"""
      .-=========-.
      \'-=======-'/     ORDER CONFIRMED
      _|   .=.   |_
     ((|  {{1}}  |))
      \|   /|\   |/
       \__ '`' __/
         _`) (`_
       _/_______\_
      /___________\
    """)

    print(f"Order ID: {order_id}")
    print(f"Total:    {money(total)}")
    print("Status:   " + ("REVIEW" if flagged else "APPROVED (simulated)"))
    pause()



def show_order_history(username: str) -> None:
    clear_screen()
    print("ORDER HISTORY")
    hr()
    user_orders = [o for o in ORDERS if o.buyer == username]
    
    if not user_orders:
        print(f"(no orders yet)")
        pause()
        return
    
    for o in reversed(user_orders[-10:]):
        print(f"{o.order_id} | {o.created_at.isoformat(timespec='seconds')}Z | {money(o.total)} | {o.payment_method} | flagged={o.fraud_flagged}")
    pause()


def seller_tools(sess: Session) -> None:
    if not can_access_seller_tools(sess.user):
        print("Access denied.")
        pause()
        return

    while True:
        clear_screen()
        print("SELLER TOOLS")
        hr()
        print("1) Add product")
        print("2) View my products")
        print("3) Back")
        c = safe_int("Select: ", 1, 3)

        if c == 1:
            add_product(sess.user.username)
        elif c == 2:
            view_seller_products(sess.user.username)
        else:
            return
        

def add_product(seller_username: str) -> None:
    clear_screen()
    print("ADD PRODUCT")
    hr()
    sku = input("SKU (e.g, SKU2001): ").strip().upper()
    
    if not sku.startswith("SKU") or len(sku) < 6:
        print("SKU should be formated as (SKUXXXX).")
        pause()
        return
    
    if sku in PRODUCTS:
        print("SKU already exists.")
        pause()
        return
    name = input("Name: ").strip()
    price = safe_float("Price: ", 0.01, 99999.0)
    stock = safe_int("Stock qty: ", 0, 100000)
    trending = input("Trending? (y/N): ").strip().lower() == "y"
    on_sale = input("On sale? (y/N): ").strip().lower() == "y"

    PRODUCTS[sku] = Product(sku, name, price, stock, trending=trending, on_sale=on_sale, seller=seller_username)
    print("Product {name}, added.")
    pause()


def view_seller_products(seller_username: str) -> None:
    clear_screen()
    print("MY PRODUCTS")
    hr()
    mine = [product for product in PRODUCTS.values() if product.seller == seller_username]
    
    if not mine:
        print(f"(none)")
        pause()
        return
    
    for product in mine:
        tags = []
        
        if product.trending: tags.append("TRENDING")
        if product.on_sale: tags.append("SALE")
        
        tag_str = f" [{' '.join(tags)}]" if tags else ""
        print(f"{product.sku} - {product.name}{tag_str} | {money(product.price)} | stock={product.in_stock}")
    pause()


def admin_tools(sess: Session) -> None:
    
    if not can_access_admin(sess.user):
        print("Access denied.")
        pause()
        return
    
    while True:
        clear_screen()
        print("ADMIN TOOLS")
        hr()
        print("1) List users")
        print("2) Create user")
        print("3) Lock/unlock user")
        print("4) Back")
        c = safe_int("Select: ", 1, 4)

        if c == 1:
            list_users()
        elif c == 2:
            create_user()
        elif c == 3:
            toggle_lock_user()
        else:
            return


def list_users() -> None:
    clear_screen()
    print("USERS")
    hr()
   
    for u in USERS.values():
        print(f"{u.username:10} role={u.role:6} locked={u.locked} failed={u.failed_attempts}")
    
    pause()


def create_user() -> None:
    clear_screen()
    print("CREATE USER")
    hr()
    username = input("Username: ").strip()
    
    if not username or username in USERS:
        print("Invalid or already exists.")
        pause()
        return
    
    password = input("Password: ").strip()
    print("Role options:")
    print("1) Buyer")
    print("2) Seller")
    print("3) Admin")
    r = safe_int("Select: ", 1, 3)
    role = [ROLE_BUYER, ROLE_SELLER, ROLE_ADMIN][r - 1]
    USERS[username] = User(username=username, password=password, role=role)
    print("User created.")
    pause()


def toggle_lock_user() -> None:
    clear_screen()
    hr()
    username = input("Username: ").strip()
    u = USERS.get(username)

    if not u:
        print("User is invalid or does not exist.")
        pause()
        return
    u.locked = not u.locked

    if not u.locked:
        u.failed_attempts = 0

    print(f"{username} locked={u.locked}")
    pause()


def run_app() -> None:
    while True:
        sess = login_screen()
        if sess is None:
            # allow retry or exit
            clear_screen()
            print("1) Try again")
            print("2) Exit")
            c = safe_int("Select: ", 1, 2)

            if c == 2:
                return
            continue
        main_menu(sess)
    
if __name__ == "__main__":
    try:
        run_app()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
