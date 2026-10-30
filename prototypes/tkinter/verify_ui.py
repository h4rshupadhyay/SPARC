"""Real-widget smoke checks. Run on a private display, never real SPARC data."""

import argparse
import os
from pathlib import Path
from unittest.mock import patch

# CustomTkinter normally copies drawing fonts to ~/.fonts on import. Keep the
# verification cache private without changing HOME or the installed library.
font_cache = Path(__file__).resolve().parents[2] / ".tools" / "fonts"
font_cache.mkdir(parents=True, exist_ok=True)
fontconfig = font_cache.parent / "fontconfig.xml"
fontconfig.write_text(f'<fontconfig><include>/etc/fonts/fonts.conf</include><dir>{font_cache}</dir><cachedir>{font_cache.parent / "cache"}</cachedir></fontconfig>')
os.environ["FONTCONFIG_FILE"] = str(fontconfig)
os.environ["XDG_CACHE_HOME"] = str(font_cache.parent / "cache")
expanduser = os.path.expanduser
with patch("os.path.expanduser", side_effect=lambda value: str(font_cache) if value == "~/.fonts/" else expanduser(value)):
    from app import PrototypeApp


def capture(app, output, names=None):
    from PIL import ImageGrab
    output.mkdir(parents=True, exist_ok=True)
    for mode in ("Light", "Dark"):
        app.set_appearance(mode)
        for size, dimensions in (("wide", "1180x780"), ("compact", "760x600")):
            app.geometry(dimensions)
            for name in names or app.views:
                app.show_view(name)
                app.update()
                x, y = app.winfo_rootx(), app.winfo_rooty()
                ImageGrab.grab(bbox=(x, y, x + app.winfo_width(), y + app.winfo_height()),
                               xdisplay=os.environ.get("DISPLAY")).save(output / f"{name.lower()}-{mode.lower()}-{size}.png")


def check_chat(app):
    app.update()
    assert app.current_view == "Chat"
    chat = app.views["Chat"]
    assert chat.state is app.demo
    assert app.demo_label.cget("text") == "Demo · Mock data"
    before = len(app.demo.messages)
    chat.composer.insert("1.0", "  \n")
    chat.send()
    assert len(app.demo.messages) == before
    chat.composer.delete("1.0", "end")
    app.demo.disconnect()
    app.refresh_views()
    assert chat.send_button.cget("state") == "disabled"
    chat.composer.insert("1.0", "hello")
    chat.send()
    assert len(app.demo.messages) == before
    app.demo.connect("192.0.2.24", "47655")
    app.refresh_views()
    chat.send_button.invoke()
    assert app.demo.messages[-1].text == "hello"
    assert len(app.demo.messages) == before + 1
    app.update()
    assert chat.composer.winfo_rooty() + chat.composer.winfo_height() <= app.winfo_rooty() + app.winfo_height()
    assert chat.history._parent_canvas.yview()[1] >= 0.99, "Newly sent message must be visible"


def check_views(app):
    assert set(app.views) == {"Connection", "Chat", "Audit", "Analysis"}
    for name in app.views:
        app.nav[name].invoke()
        app.update()
        assert app.current_view == name and app.views[name].winfo_ismapped()
    connection = app.views["Connection"]
    connection.disconnect_button.invoke()
    assert not app.demo.connected
    assert app.views["Chat"].send_button.cget("state") == "disabled"
    connection.peer_ip.delete(0, "end")
    connection.peer_ip.insert(0, "invalid")
    connection.connect_button.invoke()
    assert not app.demo.connected and connection.error.cget("text")
    connection.peer_ip.delete(0, "end")
    connection.peer_ip.insert(0, "192.0.2.24")
    connection.connect_button.invoke()
    assert app.demo.connected and not connection.error.cget("text")
    assert app.views["Chat"].send_button.cget("state") == "normal"
    connection.listener_button.invoke()
    assert app.demo.listening and "Listening" in connection.listener_status.cget("text")
    connection.listener_button.invoke()
    assert not app.demo.listening
    connection.approve_button.invoke()
    assert app.demo.pairing == "approved"
    app.demo.pairing = "pending"
    app.refresh_views()
    connection.reject_button.invoke()
    assert app.demo.pairing == "rejected"
    app.views["Audit"].verify_button.invoke()
    assert app.demo.audit_verified and "24" in app.views["Audit"].result.cget("text")
    app.views["Analysis"].run_button.invoke()
    assert app.demo.analysis_run == 1
    assert "0.18" in app.views["Analysis"].values["encrypt_ms"].cget("text")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    app = PrototypeApp()
    initial_messages = list(app.demo.messages)
    callback_errors = []
    app.report_callback_exception = lambda _kind, error, _trace: callback_errors.append(error)
    try:
        check_chat(app)
        check_views(app)
        assert not callback_errors, callback_errors
        if args.output:
            app.demo.messages[:] = initial_messages
            app.views["Chat"].selected_id = 3
            app.refresh_views()
            app.views["Chat"].history._parent_canvas.yview_moveto(0)
            capture(app, args.output)
        print("PASS: initial Chat, shared mock state, empty send, disconnected send, connected send, visible composer")
    finally:
        app.close()


if __name__ == "__main__":
    main()
