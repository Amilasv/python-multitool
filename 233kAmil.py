"""
main.py — MultiTool GUI (full)
- customtkinter UI
- Login/Register (users.json, pbkdf2)
- Weather (open-meteo geocoding + current_weather)
- Password Manager (Fernet encrypted passwords)
- Music Player (pygame)
- To-Do List (todos.json)
- Currency Dashboard + Converter (left: live rates with up/down; right: converter)
Author: delivered to you. Paste & run: python main.py
"""

import os
import json
import threading
import time
import hashlib
import base64
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, filedialog

# External libs
try:
    import customtkinter as ctk
except Exception as e:
    raise RuntimeError("customtkinter is required. Install: pip install customtkinter") from e

try:
    import requests
except Exception as e:
    raise RuntimeError("requests is required. Install: pip install requests") from e

try:
    from cryptography.fernet import Fernet
except Exception as e:
    raise RuntimeError("cryptography is required. Install: pip install cryptography") from e

try:
    import pygame
except Exception as e:
    raise RuntimeError("pygame is required. Install: pip install pygame") from e

# ---------------------------
# App files & constants
# ---------------------------
APP_DIR = Path.home() / ".multitool_app"
APP_DIR.mkdir(parents=True, exist_ok=True)

USERS_FILE = APP_DIR / "users.json"
PASSWORDS_FILE = APP_DIR / "passwords.bin"
FERNET_KEY_FILE = APP_DIR / "secret.key"
TODOS_FILE = APP_DIR / "todos.json"

# ---------------------------
# Utils: pbkdf2 + Fernet
# ---------------------------
def pbkdf2_hash(password: str) -> str:
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
    return base64.b64encode(salt + hashed).decode()

def pbkdf2_verify(stored_b64: str, password: str) -> bool:
    try:
        data = base64.b64decode(stored_b64.encode())
        salt = data[:16]
        stored_hash = data[16:]
        new_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
        return new_hash == stored_hash
    except Exception:
        return False

def get_fernet():
    if not FERNET_KEY_FILE.exists():
        key = Fernet.generate_key()
        FERNET_KEY_FILE.write_bytes(key)
    else:
        key = FERNET_KEY_FILE.read_bytes()
    return Fernet(key)

FERNET = get_fernet()

# ---------------------------
# Data load/save helpers
# ---------------------------
def load_users():
    if USERS_FILE.exists():
        try:
            return json.loads(USERS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8")

def load_passwords():
    if not PASSWORDS_FILE.exists():
        return {}
    try:
        raw = PASSWORDS_FILE.read_bytes()
        dec = FERNET.decrypt(raw)
        return json.loads(dec.decode("utf-8"))
    except Exception:
        return {}

def save_passwords(data: dict):
    raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    enc = FERNET.encrypt(raw)
    PASSWORDS_FILE.write_bytes(enc)

def load_todos():
    if not TODOS_FILE.exists():
        return []
    try:
        return json.loads(TODOS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

def save_todos(todos):
    TODOS_FILE.write_text(json.dumps(todos, indent=2, ensure_ascii=False), encoding="utf-8")

# ---------------------------
# Music init
# ---------------------------
pygame.init()
try:
    pygame.mixer.init()
except Exception:
    pass

MUSIC_STATE = {"playlist": [], "index": 0}

def play_music_file(path):
    try:
        pygame.mixer.music.load(path)
        pygame.mixer.music.play()
    except Exception as e:
        messagebox.showerror("Music Error", f"Could not play file:\n{e}")

# ---------------------------
# Currency rates manager
# ---------------------------
# We'll use https://open.er-api.com/v6/latest/USD which returns rates keyed by currency.
# Keep previous rates in-memory to compute up/down change.
class RatesFetcher:
    def __init__(self, base="USD"):
        self.base = base
        self.rates = {}         # latest rates
        self.prev_rates = {}    # previous snapshot
        self.lock = threading.Lock()
        self.running = False

    def fetch_once(self):
        url = f"https://open.er-api.com/v6/latest/{self.base}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        if "rates" in data:
            with self.lock:
                self.prev_rates = self.rates.copy()
                self.rates = data["rates"].copy()
            return True
        return False

    def start_periodic(self, interval=60):
        if self.running:
            return
        self.running = True
        def loop():
            while self.running:
                try:
                    self.fetch_once()
                except Exception:
                    pass
                time.sleep(interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def stop(self):
        self.running = False

    def get_rates_snapshot(self):
        with self.lock:
            return self.rates.copy(), self.prev_rates.copy()

# instantiate a global fetcher
RATES_FETCHER = RatesFetcher(base="USD")
# try initial fetch (non-blocking thread)
try:
    RATES_FETCHER.fetch_once()
except Exception:
    pass
RATES_FETCHER.start_periodic(interval=60)

# ---------------------------
# UI Setup
# ---------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class MultiToolApp:
    def __init__(self, root):
        self.root = root
        root.title("MultiTool — All-in-one")
        root.geometry("980x640")
        root.resizable(False, False)

        self.main_frame = ctk.CTkFrame(root, corner_radius=12)
        self.main_frame.pack(fill="both", expand=True, padx=16, pady=16)

        header = ctk.CTkLabel(self.main_frame, text="MultiTool", font=("Roboto", 34, "bold"))
        header.pack(pady=(8,4))
        sub = ctk.CTkLabel(self.main_frame, text="Weather · Passwords · Music · To-Do · Currency · Login", font=("Roboto", 14))
        sub.pack(pady=(0,12))
        self.build_buttons()

        # Show login on startup (modal)
        self.show_login_window()

    def build_buttons(self):
        grid = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        grid.pack(expand=True)

        def make_button(text, color, cmd):
            return ctk.CTkButton(grid, text=text, width=300, height=90, fg_color=color, corner_radius=14, font=("Roboto", 14, "bold"), command=cmd)

        b_weather = make_button("Weather — Hava haqqında məlumat", "#89dceb", self.open_weather)
        b_passwords = make_button("Password Manager", "#f38ba8", self.open_passwords)
        b_music = make_button("Music Player", "#bde0fe", self.open_music)
        b_todo = make_button("To-Do List", "#c7f9cc", self.open_todo)
        b_currency = make_button("Currency Converter", "#ffd6a5", self.open_currency)
        b_auth = make_button("Logout / Switch User", "#cdb4db", self.show_login_window)

        b_weather.grid(row=0, column=0, padx=18, pady=14)
        b_passwords.grid(row=0, column=1, padx=18, pady=14)
        b_music.grid(row=1, column=0, padx=18, pady=14)
        b_todo.grid(row=1, column=1, padx=18, pady=14)
        b_currency.grid(row=2, column=0, padx=18, pady=14)
        b_auth.grid(row=2, column=1, padx=18, pady=14)

    # ---------------------------
    # Auth windows: login + register
    # ---------------------------
    def show_login_window(self):
        login_win = ctk.CTkToplevel(self.root)
        login_win.title("Login or Register")
        login_win.geometry("420x420")
        login_win.resizable(False, False)
        login_win.grab_set()

        lbl = ctk.CTkLabel(login_win, text="Welcome — Login or Register", font=("Roboto", 20, "bold"))
        lbl.pack(pady=(18,8))

        username = ctk.CTkEntry(login_win, width=280, placeholder_text="Username")
        username.pack(pady=8)
        password = ctk.CTkEntry(login_win, width=280, placeholder_text="Password", show="*")
        password.pack(pady=8)
        status_lbl = ctk.CTkLabel(login_win, text="", font=("Roboto", 12))
        status_lbl.pack(pady=(4,8))

        def do_login():
            u = username.get().strip()
            p = password.get().strip()
            if not u or not p:
                status_lbl.configure(text="Fill both fields", text_color="red")
                return
            users = load_users()
            if u in users and pbkdf2_verify(users[u], p):
                status_lbl.configure(text="Login successful", text_color="green")
                login_win.grab_release()
                login_win.destroy()
                return
            else:
                status_lbl.configure(text="Invalid username or password", text_color="red")

        def open_register():
            reg = ctk.CTkToplevel(self.root)
            reg.title("Register")
            reg.geometry("420x460")
            reg.resizable(False, False)
            reg.grab_set()

            ctk.CTkLabel(reg, text="Create account", font=("Roboto", 18, "bold")).pack(pady=(12,6))
            r_user = ctk.CTkEntry(reg, width=300, placeholder_text="Username")
            r_user.pack(pady=8)
            r_pass = ctk.CTkEntry(reg, width=300, placeholder_text="Password", show="*")
            r_pass.pack(pady=8)
            r_pass2 = ctk.CTkEntry(reg, width=300, placeholder_text="Repeat Password", show="*")
            r_pass2.pack(pady=8)
            r_status = ctk.CTkLabel(reg, text="", font=("Roboto", 12))
            r_status.pack(pady=(6,8))

            def do_register_action():
                u = r_user.get().strip()
                p1 = r_pass.get().strip()
                p2 = r_pass2.get().strip()
                if not u or not p1:
                    r_status.configure(text="Fields cannot be empty", text_color="red")
                    return
                if p1 != p2:
                    r_status.configure(text="Passwords do not match", text_color="red")
                    return
                users = load_users()
                if u in users:
                    r_status.configure(text="User already exists", text_color="red")
                    return
                users[u] = pbkdf2_hash(p1)
                save_users(users)
                r_status.configure(text="Account created! You can login now.", text_color="green")
                reg.after(900, lambda: (reg.grab_release(), reg.destroy()))

            ctk.CTkButton(reg, text="Register", width=200, command=do_register_action).pack(pady=12)
            ctk.CTkButton(reg, text="Cancel", width=200, fg_color="#777", hover_color="#999", command=lambda: (reg.grab_release(), reg.destroy())).pack(pady=6)

        ctk.CTkButton(login_win, text="Login", width=220, command=do_login).pack(pady=10)
        ctk.CTkButton(login_win, text="Register", width=220, fg_color="#555", hover_color="#777", command=open_register).pack(pady=6)

    # ---------------------------
    # Weather
    # ---------------------------
    def open_weather(self):
        win = ctk.CTkToplevel(self.root)
        win.title("Weather")
        win.geometry("520x360")
        win.resizable(False, False)

        ctk.CTkLabel(win, text="Weather — enter city name", font=("Roboto", 16, "bold")).pack(pady=(10,6))
        city_entry = ctk.CTkEntry(win, width=380, placeholder_text="e.g. Baku")
        city_entry.pack(pady=8)

        result = ctk.CTkLabel(win, text="", justify="left", wraplength=480)
        result.pack(pady=10)

        def get_coords(city):
            try:
                url = f"https://geocoding-api.open-meteo.com/v1/search?name={requests.utils.quote(city)}&count=1"
                r = requests.get(url, timeout=8)
                r.raise_for_status()
                data = r.json()
                if "results" in data and len(data["results"])>0:
                    res = data["results"][0]
                    return res["latitude"], res["longitude"], res.get("country","")
                return None
            except Exception:
                return None

        def fetch_weather():
            city = city_entry.get().strip()
            if not city:
                result.configure(text="Enter city name", text_color="red")
                return
            result.configure(text="Loading...")
            def worker():
                coords = get_coords(city)
                if not coords:
                    result.configure(text="City not found or network error.", text_color="red")
                    return
                lat, lon, country = coords
                try:
                    url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current_weather=true"
                    r = requests.get(url, timeout=8)
                    r.raise_for_status()
                    data = r.json()
                    cur = data.get("current_weather", {})
                    temp = cur.get("temperature")
                    wind = cur.get("windspeed")
                    time_str = cur.get("time")
                    text = f"City: {city}, {country}\nTemperature: {temp}°C\nWind speed: {wind} m/s\nTime (UTC): {time_str}"
                    result.configure(text=text, text_color="white")
                except Exception as e:
                    result.configure(text=f"Weather fetch error: {e}", text_color="red")
            threading.Thread(target=worker, daemon=True).start()

        ctk.CTkButton(win, text="Get Weather", width=200, command=fetch_weather).pack(pady=8)

    # ---------------------------
    # Password Manager
    # ---------------------------
    def open_passwords(self):
        win = ctk.CTkToplevel(self.root)
        win.title("Password Manager")
        win.geometry("760x460")
        win.resizable(False, False)

        frame = ctk.CTkFrame(win)
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        left = ctk.CTkFrame(frame, width=240)
        left.pack(side="left", fill="y", padx=(0,8), pady=4)
        right = ctk.CTkFrame(frame)
        right.pack(side="left", fill="both", expand=True, padx=(8,0), pady=4)

        ctk.CTkLabel(left, text="Saved Sites", font=("Roboto", 16, "bold")).pack(pady=(6,8))
        listbox = tk.Listbox(left, width=28, height=24)
        listbox.pack(padx=8, pady=6)

        data = load_passwords()
        for k in data.keys():
            listbox.insert("end", k)

        site_e = ctk.CTkEntry(right, width=380, placeholder_text="Site / Name")
        site_e.pack(pady=(12,6))
        user_e = ctk.CTkEntry(right, width=380, placeholder_text="Username / Email")
        user_e.pack(pady=6)
        pass_e = ctk.CTkEntry(right, width=380, placeholder_text="Password")
        pass_e.pack(pady=6)
        info_lbl = ctk.CTkLabel(right, text="", font=("Roboto", 11))
        info_lbl.pack(pady=6)

        def refresh_list():
            listbox.delete(0, "end")
            for s in data.keys():
                listbox.insert("end", s)

        def on_select(evt=None):
            sel = listbox.curselection()
            if not sel: return
            key = listbox.get(sel[0])
            info = data.get(key, {})
            site_e.delete(0, "end"); site_e.insert(0, key)
            user_e.delete(0, "end"); user_e.insert(0, info.get("username",""))
            pass_e.delete(0, "end"); pass_e.insert(0, info.get("password",""))

        def save_entry():
            site = site_e.get().strip()
            if not site:
                messagebox.showinfo("Info", "Enter site name")
                return
            data[site] = {"username": user_e.get().strip(), "password": pass_e.get().strip(), "updated": datetime.utcnow().isoformat()}
            save_passwords(data)
            refresh_list()
            info_lbl.configure(text="Saved (encrypted).")

        def delete_entry():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Info", "Select an item to delete")
                return
            key = listbox.get(sel[0])
            if key in data:
                del data[key]
                save_passwords(data)
                refresh_list()
                site_e.delete(0,"end"); user_e.delete(0,"end"); pass_e.delete(0,"end")
                info_lbl.configure(text="Deleted.")

        def gen_password(length=14):
            import secrets, string
            chars = string.ascii_letters + string.digits + string.punctuation
            pwd = "".join(secrets.choice(chars) for _ in range(length))
            pass_e.delete(0,"end"); pass_e.insert(0,pwd)
            info_lbl.configure(text="Generated random password.")

        btn_frame = ctk.CTkFrame(right)
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Save", width=120, command=save_entry).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Delete", width=120, fg_color="#f06", hover_color="#f38", command=delete_entry).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Generate", width=120, fg_color="#7bd", command=lambda: gen_password(14)).pack(side="left", padx=6)

        listbox.bind("<<ListboxSelect>>", on_select)

    # ---------------------------
    # Music Player
    # ---------------------------
    def open_music(self):
        win = ctk.CTkToplevel(self.root)
        win.title("Music Player")
        win.geometry("760x460")
        win.resizable(False, False)

        frame = ctk.CTkFrame(win)
        frame.pack(fill="both", expand=True, padx=12, pady=12)
        left = ctk.CTkFrame(frame, width=320)
        left.pack(side="left", fill="y", padx=(0,8))
        right = ctk.CTkFrame(frame)
        right.pack(side="left", fill="both", expand=True, padx=(8,0))

        ctk.CTkLabel(left, text="Playlist", font=("Roboto", 16, "bold")).pack(pady=(6,8))
        playlist_box = tk.Listbox(left, width=38, height=24)
        playlist_box.pack(padx=8, pady=6)

        for p in MUSIC_STATE["playlist"]:
            playlist_box.insert("end", os.path.basename(p))

        def add_files():
            files = filedialog.askopenfilenames(title="Choose audio files", filetypes=[("Audio files","*.mp3;*.wav;*.ogg"),("All files","*.*")])
            if not files:
                return
            for f in files:
                MUSIC_STATE["playlist"].append(f)
                playlist_box.insert("end", os.path.basename(f))

        def play_selected():
            sel = playlist_box.curselection()
            if sel:
                MUSIC_STATE["index"] = sel[0]
            idx = MUSIC_STATE["index"]
            if 0 <= idx < len(MUSIC_STATE["playlist"]):
                path = MUSIC_STATE["playlist"][idx]
                play_music_file(path)

        def pause_toggle():
            try:
                if pygame.mixer.music.get_busy():
                    pygame.mixer.music.pause()
                else:
                    pygame.mixer.music.unpause()
            except Exception:
                pass

        def stop_music():
            try:
                pygame.mixer.music.stop()
            except Exception:
                pass

        def next_track():
            if MUSIC_STATE["playlist"]:
                MUSIC_STATE["index"] = (MUSIC_STATE["index"] + 1) % len(MUSIC_STATE["playlist"])
                play_selected()

        def prev_track():
            if MUSIC_STATE["playlist"]:
                MUSIC_STATE["index"] = (MUSIC_STATE["index"] - 1) % len(MUSIC_STATE["playlist"])
                play_selected()

        btns = ctk.CTkFrame(right)
        btns.pack(pady=8)
        ctk.CTkButton(btns, text="Add files", width=140, command=add_files).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Play", width=100, command=play_selected).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Pause/Resume", width=160, command=pause_toggle).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Stop", width=100, command=stop_music, fg_color="#f06").pack(side="left", padx=6)

        navs = ctk.CTkFrame(right)
        navs.pack(pady=8)
        ctk.CTkButton(navs, text="Prev", width=100, command=prev_track).pack(side="left", padx=8)
        ctk.CTkButton(navs, text="Next", width=100, command=next_track).pack(side="left", padx=8)

        ctk.CTkLabel(right, text="Volume").pack(pady=(16,6))
        vol = ctk.CTkSlider(right, from_=0, to=100, number_of_steps=100, width=300)
        vol.set(80)
        def set_vol(v):
            try:
                pygame.mixer.music.set_volume(float(v)/100.0)
            except Exception:
                pass
        vol.configure(command=set_vol)
        vol.pack()

    # ---------------------------
    # To-Do List
    # ---------------------------
    def open_todo(self):
        win = ctk.CTkToplevel(self.root)
        win.title("To-Do List")
        win.geometry("640x460")
        win.resizable(False, False)

        todos = load_todos()
        frame = ctk.CTkFrame(win)
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        listbox = tk.Listbox(frame, width=70, height=20)
        listbox.pack(pady=8)
        for t in todos:
            status = "[x]" if t.get("done") else "[ ]"
            listbox.insert("end", f"{status} {t.get('task')}")

        entry = ctk.CTkEntry(frame, width=500, placeholder_text="New task")
        entry.pack(pady=6)

        def add_task():
            text = entry.get().strip()
            if not text:
                return
            todos.append({"task": text, "done": False, "created": datetime.utcnow().isoformat()})
            listbox.insert("end", f"[ ] {text}")
            entry.delete(0,"end")
            save_todos(todos)

        def toggle_done():
            sel = listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            todos[idx]["done"] = not todos[idx].get("done", False)
            status = "[x]" if todos[idx]["done"] else "[ ]"
            listbox.delete(idx)
            listbox.insert(idx, f"{status} {todos[idx]['task']}")
            save_todos(todos)

        def delete_task():
            sel = listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            todos.pop(idx)
            listbox.delete(idx)
            save_todos(todos)

        btnf = ctk.CTkFrame(frame)
        btnf.pack(pady=8)
        ctk.CTkButton(btnf, text="Add Task", width=140, command=add_task).pack(side="left", padx=6)
        ctk.CTkButton(btnf, text="Toggle Done", width=140, command=toggle_done).pack(side="left", padx=6)
        ctk.CTkButton(btnf, text="Delete", width=140, command=delete_task, fg_color="#f06").pack(side="left", padx=6)

    # ---------------------------
    # Currency Dashboard & Converter
    # ---------------------------
    def open_currency(self):
        win = ctk.CTkToplevel(self.root)
        win.title("Currency Dashboard + Converter")
        win.geometry("980x600")
        win.resizable(False, False)

        left_frame = ctk.CTkFrame(win, width=380)
        left_frame.pack(side="left", fill="y", padx=12, pady=12)
        right_frame = ctk.CTkFrame(win)
        right_frame.pack(side="left", fill="both", expand=True, padx=(0,12), pady=12)

        # LEFT: title + scrollable list
        ctk.CTkLabel(left_frame, text="📊 Live Currency Rates (base USD)", font=("Roboto", 16, "bold")).pack(pady=(8,8))
        scroll = ctk.CTkScrollableFrame(left_frame, width=360, height=520)
        scroll.pack(pady=(6,0))

        # We'll populate rates into rows inside 'scroll'
        rate_rows = {}  # key -> (frame, label_rate, label_delta)

        def load_and_display_rates():
            rates, prev = RATES_FETCHER.get_rates_snapshot()
            scroll_children = scroll.winfo_children()
            # clear old widgets
            for w in scroll_children:
                w.destroy()
            if not rates:
                ctk.CTkLabel(scroll, text="Failed to fetch rates.").pack(pady=6)
                return

            # Determine a sorted list of currencies: show important first, then rest alphabetical
            important = ["USD","EUR","GBP","TRY","RUB","AZN","JPY","CHF","CNY","KWD"]
            others = sorted([c for c in rates.keys() if c not in important])
            display_list = [c for c in important if c in rates] + others

            for cur in display_list:
                val = rates[cur]
                prev_val = prev.get(cur)
                delta_text = ""
                delta_color = "white"
                if prev_val:
                    diff = val - prev_val
                    if diff > 0:
                        delta_text = f"↑ {round(diff,6)}"
                        delta_color = "#7CFC00"  # light green for up
                    elif diff < 0:
                        delta_text = f"↓ {round(-diff,6)}"
                        delta_color = "#FF6B6B"  # pink/red for down
                    else:
                        delta_text = "—"
                        delta_color = "white"
                else:
                    delta_text = "—"
                    delta_color = "white"

                row = ctk.CTkFrame(scroll)
                row.pack(fill="x", pady=6, padx=6)

                cur_lbl = ctk.CTkLabel(row, text=cur, width=80, anchor="w", font=("Roboto", 12, "bold"))
                cur_lbl.pack(side="left")
                rate_lbl = ctk.CTkLabel(row, text=f"{round(val,6)}", anchor="e", width=160)
                rate_lbl.pack(side="right", padx=(0,10))
                delta_lbl = ctk.CTkLabel(row, text=delta_text, anchor="e", width=80, text_color=delta_color)
                delta_lbl.pack(side="right", padx=(0,6))

        # initial display
        load_and_display_rates()

        # Periodically refresh UI (every 10s, but underlying fetcher updates every 60s)
        def periodic_ui_update():
            while True:
                try:
                    load_and_display_rates()
                except Exception:
                    pass
                time.sleep(10)
        t = threading.Thread(target=periodic_ui_update, daemon=True)
        t.start()

        # RIGHT: Converter UI
        ctk.CTkLabel(right_frame, text="💱 Converter", font=("Roboto", 18, "bold")).pack(pady=(12,6))
        conv_frame = ctk.CTkFrame(right_frame)
        conv_frame.pack(pady=8, padx=12, fill="x")

        amt_entry = ctk.CTkEntry(conv_frame, width=200, placeholder_text="Amount")
        amt_entry.pack(pady=8)

        # We'll fetch current currencies to populate comboboxes
        rates_now, _ = RATES_FETCHER.get_rates_snapshot()
        currency_list = sorted(list(rates_now.keys())) if rates_now else ["USD","EUR","AZN","TRY","GBP","RUB"]

        from_cb = ctk.CTkComboBox(conv_frame, values=currency_list, width=180)
        from_cb.set("USD")
        from_cb.pack(pady=6)
        to_cb = ctk.CTkComboBox(conv_frame, values=currency_list, width=180)
        to_cb.set("AZN")
        to_cb.pack(pady=6)

        result_lbl = ctk.CTkLabel(conv_frame, text="", font=("Roboto", 16))
        result_lbl.pack(pady=12)

        def do_convert():
            try:
                amt = float(amt_entry.get().strip())
            except Exception:
                result_lbl.configure(text="Invalid amount", text_color="red")
                return
            frm = from_cb.get().strip().upper()
            to = to_cb.get().strip().upper()
            # fetch latest snapshot then compute
            rates, _ = RATES_FETCHER.get_rates_snapshot()
            if not rates:
                result_lbl.configure(text="Rates unavailable", text_color="red")
                return
            if frm not in rates or to not in rates:
                result_lbl.configure(text="Invalid currency code", text_color="red")
                return
            try:
                # convert: amount_in_usd = amt / rate[frm]; final = amount_in_usd * rate[to]
                amount_in_usd = amt / rates[frm]
                final = amount_in_usd * rates[to]
                result_lbl.configure(text=f"{amt} {frm} = {round(final,6)} {to}", text_color="white")
            except Exception as e:
                result_lbl.configure(text=f"Error: {e}", text_color="red")

        ctk.CTkButton(conv_frame, text="Convert", width=200, command=do_convert).pack(pady=6)

        # Extra: Refresh rates button and reload combobox list
        def refresh_now():
            try:
                RATES_FETCHER.fetch_once()
                # update combobox choices
                r, _ = RATES_FETCHER.get_rates_snapshot()
                keys = sorted(list(r.keys()))
                from_cb.configure(values=keys)
                to_cb.configure(values=keys)
                # update left display immediately
                load_and_display_rates()
            except Exception as e:
                messagebox.showerror("Error", f"Could not refresh rates:\n{e}")

        ctk.CTkButton(right_frame, text="Refresh Rates Now", width=220, command=refresh_now).pack(pady=(6,0))

    # end open_currency

# ---------------------------
# Run app
# ---------------------------
def main():
    root = ctk.CTk()
    app = MultiToolApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
