"""Shared, restrained desktop tokens. Colors are (light, dark)."""

import customtkinter as ctk
from tkinter import font as tkfont

BACKGROUND = ("#FFFFFF", "#141C26")
SIDEBAR = ("#F3F5F8", "#101720")
SURFACE = ("#F3F5F8", "#1C2633")
HOVER = ("#E4EAF2", "#29374A")
TEXT = ("#172536", "#E6EDF5")
MUTED = ("#526176", "#A6B4C6")
BLUE = ("#205FC0", "#3B76D3")
BLUE_HOVER = ("#174A99", "#3266B5")
SELECTED = ("#E3ECFA", "#253A58")
OUTGOING = ("#E7EFFC", "#223750")
BORDER = ("#D5DDE8", "#354358")
ERROR = ("#A12A32", "#F0A1A6")
INTERNAL = {"padx": 10, "pady": 5, "sticky": "nsew"}
MAIN = {"padx": 20, "pady": 20, "sticky": "nsew"}
RADIUS = 6


def initialize() -> None:
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")


def font(role: str = "body") -> ctk.CTkFont:
    family = "Segoe UI" if "Segoe UI" in tkfont.families() else "Arial"
    size, weight = {"heading": (24, "bold"), "subheading": (16, "bold"), "body": (12, "normal")}[role]
    return ctk.CTkFont(family=family, size=size, weight=weight)
