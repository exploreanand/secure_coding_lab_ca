"""
Secure Coding Lab CA - Python Implementation (Minimal)
Demonstrates 5 Secure Coding Features:
  1. Input Validation (whitelist)
  2. Secure Password Storage (PBKDF2-SHA256 + Salt + 200,000 iterations)
  3. Authentication with Account Lockout
  4. Authorization / Access Control (roles)
  5. Secure Error Handling & Logging
"""

import re, json, hmac, hashlib, secrets, logging, time, os, getpass

DB, LOG, MAX_ATTEMPTS, LOCKOUT = "users.json", "app.log", 3, 60

# Feature 5: Secure logging (never logs passwords)
logging.basicConfig(filename=LOG, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# Feature 1: Input validation (whitelist)
valid_user = lambda u: bool(re.fullmatch(r"[A-Za-z0-9_]{3,20}", u))
valid_role = lambda r: r in ("user", "admin")
def valid_pwd(p):
    return (8 <= len(p) <= 64 and any(c.isupper() for c in p)
            and any(c.islower() for c in p) and any(c.isdigit() for c in p)
            and any(not c.isalnum() for c in p))

# Feature 2: Salted PBKDF2 password hashing
def hash_pwd(pwd, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt), 200_000).hex()
    return h, salt

# File-backed user store
def load(): return json.load(open(DB)) if os.path.exists(DB) else {}
def save(db): json.dump(db, open(DB, "w"), indent=2)

current = {"user": None, "role": None}

def register(u, p, role):
    if not valid_user(u): logging.warning("Reg: bad username"); return "Invalid username. Use 3-20 letters, digits, or underscore."
    if not valid_pwd(p):  logging.warning("Reg: weak pwd %s", u); return "Weak password. Need 8+ chars with upper, lower, digit, special."
    if not valid_role(role): logging.warning("Reg: bad role"); return "Role must be 'user' or 'admin'."
    db = load()
    if u in db: logging.warning("Reg: duplicate %s", u); return "Registration failed."
    h, s = hash_pwd(p)
    db[u] = {"hash": h, "salt": s, "role": role, "fails": 0, "locked": 0}
    save(db); logging.info("Registered %s (%s)", u, role)
    return "Registration successful."

def login(u, p):
    try:
        if not valid_user(u): logging.warning("Login: bad username"); return "Invalid username or password."
        db = load(); r = db.get(u)
        if not r: logging.warning("Login: unknown user"); return "Invalid username or password."
        if r["locked"] > time.time(): logging.warning("Login blocked (locked): %s", u); return "Account temporarily locked. Try again later."
        # Feature 2: constant-time compare (hmac.compare_digest prevents timing attacks)
        computed, _ = hash_pwd(p, r["salt"])
        if hmac.compare_digest(computed, r["hash"]):
            r["fails"], r["locked"] = 0, 0; save(db)
            current["user"], current["role"] = u, r["role"]
            logging.info("Login success: %s", u)
            return f"Login successful. Role: {r['role']}"
        r["fails"] += 1
        if r["fails"] >= MAX_ATTEMPTS:
            r["locked"] = int(time.time()) + LOCKOUT
            logging.warning("Account locked after %d attempts: %s", r["fails"], u)
        else:
            logging.warning("Login failed (%d/%d): %s", r["fails"], MAX_ATTEMPTS, u)
        save(db); return "Invalid username or password."
    except Exception as e:
        logging.error("Exception in login: %s", e)  # Feature 5: details in log, generic to user
        return "An error occurred. Please try again."

def logout():
    if current["user"]: logging.info("Logout: %s", current["user"])
    current["user"] = current["role"] = None

# Feature 4: Authorization / Access Control
def require_login():
    if not current["user"]: logging.warning("Unauthenticated action attempt"); print("Access denied. Please login first."); return False
    return True
def require_role(need):
    if not require_login(): return False
    if current["role"] != need:
        logging.warning("Authz failed: %s needs %s", current["user"], need)
        print(f"Access denied. Requires role: {need}"); return False
    return True
def user_action():
    if require_login(): print(f"[{current['user']}] User action performed."); logging.info("User action by %s", current['user'])
def admin_action():
    if require_role("admin"): print(f"[{current['user']}] ADMIN action performed."); logging.info("Admin action by %s", current['user'])

def main():
    logging.info("Application started")
    while True:
        who = f"{current['user']} [{current['role']}]" if current["user"] else "(none)"
        print(f"\n========= Secure App =========\nLogged in: {who}")
        print("1. Register\n2. Login\n3. Logout\n4. User Action\n5. Admin Action\n6. Quit")
        c = input("Choose: ").strip()
        try:
            if c == "1":
                u = input("Username: ").strip()
                p = getpass.getpass("Password: ")
                r = input("Role (user/admin): ").strip()
                print(register(u, p, r))
            elif c == "2":
                u = input("Username: ").strip()
                p = getpass.getpass("Password: ")
                print(login(u, p))
            elif c == "3": logout(); print("Logged out.")
            elif c == "4": user_action()
            elif c == "5": admin_action()
            elif c == "6": break
            else: print("Invalid choice.")
        except Exception as e:
            logging.error("Unhandled: %s", e); print("An error occurred. Please try again.")
    logging.info("Application exited")

if __name__ == "__main__":
    main()