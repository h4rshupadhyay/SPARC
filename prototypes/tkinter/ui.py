"""A small vocabulary for the four prototype screens."""

import customtkinter as ctk

import theme as t


def label(parent, text, role="body", muted=False, **kwargs):
    return ctk.CTkLabel(parent, text=text, font=t.font(role), text_color=t.MUTED if muted else t.TEXT,
                        anchor="w", justify="left", **kwargs)


def button(parent, text, command, primary=False, **kwargs):
    return ctk.CTkButton(parent, text=text, command=command, font=t.font(), height=36,
                         corner_radius=t.RADIUS, fg_color=t.BLUE if primary else t.SURFACE,
                         hover_color=t.BLUE_HOVER if primary else t.HOVER,
                         text_color="#FFFFFF" if primary else t.TEXT,
                         text_color_disabled=t.MUTED, **kwargs)


def section(parent, title):
    frame = ctk.CTkFrame(parent, fg_color=t.SURFACE, corner_radius=t.RADIUS)
    frame.columnconfigure(0, weight=1)
    label(frame, title, "subheading").grid(row=0, column=0, **t.MAIN)
    return frame


def field(parent, title, value, row, column=0, width=180):
    group = ctk.CTkFrame(parent, fg_color="transparent")
    group.columnconfigure(0, weight=1)
    group.grid(row=row, column=column, **t.INTERNAL)
    label(group, title, muted=True).grid(row=0, column=0, **t.INTERNAL)
    entry = ctk.CTkEntry(group, width=width, height=36, font=t.font(), text_color=t.TEXT,
                         fg_color=t.BACKGROUND, border_color=t.BORDER, corner_radius=t.RADIUS)
    entry.insert(0, value)
    entry.grid(row=1, column=0, **t.INTERNAL)
    return entry
