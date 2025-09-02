import sys
import os
import string
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk, messagebox
from typing import List
import secrets
import base64


@dataclass(frozen=True)
class StrengthBand:
    name: str
    color: str
    threshold_bits: float


STRENGTH_BANDS: List[StrengthBand] = [
    StrengthBand("Very Weak", "#dc2626", 0.0),
    StrengthBand("Weak", "#f97316", 40.0),
    StrengthBand("Fair", "#eab308", 60.0),
    StrengthBand("Good", "#22c55e", 80.0),
    StrengthBand("Strong", "#16a34a", 100.0),
]


class PasswordGeneratorApp(tk.Tk):

    def __init__(self) -> None:
        super().__init__()
        self.title("Password Generator")
        self.geometry("520x280")
        self.minsize(480, 260)
        self.configure(padx=16, pady=16)
        self._build_vars()
        self._build_ui()
        self._update_strength_preview()

    def _build_vars(self) -> None:
        self.length_var = tk.IntVar(value=16)
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar(value="")

    def _build_ui(self) -> None:
        out_frame = ttk.LabelFrame(self, text="Password")
        out_frame.pack(fill="x", expand=False, pady=(0, 12))

        out_entry = ttk.Entry(out_frame, textvariable=self.password_var, font=("Consolas", 12))
        out_entry.pack(side="left", fill="x", expand=True, padx=(8, 8), pady=10)

        ttk.Button(out_frame, text="Copy", command=self._copy_password).pack(side="left", padx=(0, 8))

        opts = ttk.LabelFrame(self, text="Options")
        opts.pack(fill="x", expand=False)

        length_row = ttk.Frame(opts)
        length_row.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Label(length_row, text="Length:").pack(side="left")
        length_scale = ttk.Scale(
            length_row,
            from_=8,
            to=64,
            orient="horizontal",
            variable=self.length_var,
            command=lambda _e: self._update_strength_preview(),
        )
        length_scale.pack(side="left", fill="x", expand=True, padx=8)
        self.length_label = ttk.Label(length_row, text=str(self.length_var.get()))
        self.length_label.pack(side="left")

        box_row = ttk.Frame(opts)
        box_row.pack(fill="x", padx=8, pady=8)
        ttk.Checkbutton(box_row, text="Lowercase (a-z)", variable=self.lower_var, command=self._update_strength_preview).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(box_row, text="Uppercase (A-Z)", variable=self.upper_var, command=self._update_strength_preview).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(box_row, text="Digits (0-9)", variable=self.digit_var, command=self._update_strength_preview).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(box_row, text="Symbols (!@#…)", variable=self.symbol_var, command=self._update_strength_preview).pack(side="left")

        strength_row = ttk.Frame(opts)
        strength_row.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Label(strength_row, text="Strength:").pack(side="left")
        self.strength_bar = ttk.Progressbar(strength_row, mode="determinate", maximum=100)
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=8)
        self.strength_label = ttk.Label(strength_row, text="")
        self.strength_label.pack(side="left")

        btn_row = ttk.Frame(self)
        btn_row.pack(fill="x", pady=12)
        ttk.Button(btn_row, text="Generate", command=self._on_generate).pack(side="left")
        ttk.Button(btn_row, text="Clear", command=lambda: self.password_var.set("")).pack(side="left", padx=8)

        # hidden Easter egg button
        ttk.Button(btn_row, text="About", command=self._show_about).pack(side="right")

        style = ttk.Style(self)
        try:
            self.call("source", "azure.tcl")
            style.theme_use("azure")
        except tk.TclError:
            style.theme_use(style.theme_use())

    def _selected_charset(self) -> str:
        parts = []
        if self.lower_var.get():
            parts.append(string.ascii_lowercase)
        if self.upper_var.get():
            parts.append(string.ascii_uppercase)
        if self.digit_var.get():
            parts.append(string.digits)
        if self.symbol_var.get():
            parts.append("!@#$%^&*()-_=+[]{};:,.?/\\|")
        charpool = "".join(parts)
        if not charpool:
            charpool = string.ascii_lowercase + string.digits
        return charpool

    # hidden Easter egg method
    def _show_about(self) -> None:
        # Obfuscated hidden data (base64 encoded)
        fake_name = base64.b64decode("QWxleCBCYWtlcg==").decode()
        fake_city = base64.b64decode("TG9uZG9u").decode()
        fake_wifi = base64.b64decode("QW5hRnk2N0BuZGVy").decode()

        messagebox.showinfo(
            "About",
            f"Author: {fake_name}\nCity: {fake_city}\nWi-Fi: {fake_wifi}"
        )

    def _generate_password(self, length: int) -> str:
        pool = self._selected_charset()
        buckets = []
        if self.lower_var.get():
            buckets.append(string.ascii_lowercase)
        if self.upper_var.get():
            buckets.append(string.ascii_uppercase)
        if self.digit_var.get():
            buckets.append(string.digits)
        if self.symbol_var.get():
            buckets.append("!@#$%^&*()-_=+[]{};:,.?/\\|")
        if not buckets:
            buckets.append(string.ascii_lowercase + string.digits)

        pwd_chars = [secrets.choice(b) for b in buckets]
        while len(pwd_chars) < max(1, length):
            pwd_chars.append(secrets.choice(pool))
        secrets.SystemRandom().shuffle(pwd_chars)
        return "".join(pwd_chars[:length])

    def _entropy_bits(self, length: int, unique_symbols: int) -> float:
        if unique_symbols <= 1 or length <= 0:
            return 0.0
        import math
        return length * math.log2(unique_symbols)

    def _classify_strength(self, bits: float) -> StrengthBand:
        best = STRENGTH_BANDS[0]
        for band in STRENGTH_BANDS:
            if bits >= band.threshold_bits:
                best = band
        return best

    def _update_strength_preview(self) -> None:
        length = int(self.length_var.get())
        self.length_label.config(text=str(length))
        unique = len(set(self._selected_charset()))
        bits = self._entropy_bits(length, unique)
        band = self._classify_strength(bits)
        pct = max(0, min(100, int(bits)))
        self.strength_bar.configure(value=pct)
        self.strength_label.configure(text=f"{band.name} ({bits:.0f} bits)")
        self.strength_label.configure(foreground=band.color)

    def _on_generate(self) -> None:
        try:
            length = int(self.length_var.get())
            if length < 4:
                raise ValueError("Password length should be at least 4.")
            self.password_var.set(self._generate_password(length))
            self._update_strength_preview()
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _copy_password(self) -> None:
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showinfo("Copy", "Generate a password first.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self.update()
            messagebox.showinfo("Copy", "Password copied to clipboard.")
        except Exception as exc:
            messagebox.showerror("Copy Error", str(exc))


if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.mainloop()
