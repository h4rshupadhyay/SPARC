# Integrated SPARC window chrome

The user requests the application-owned chrome used by desktop tools such as
VS Code, Obsidian and Chrome, without a generic operating-system title row.

Use the existing dark navigation row: SPARC at the left, tabs in the middle,
window controls at the right. Keep the measured larger fonts and minimum
800×640 content layout. Dragging on branding or unused navigation space moves
the window; double-clicking toggles maximize. Tabs retain their own click and
keyboard behavior. Thin edge handles support manual resizing. Close dispatches
the current WM_DELETE_WINDOW handler so service shutdown and identity
cancellation retain their existing ownership.

Prefer managed, undecorated windows: X11 Motif decoration hints, Windows window
styles, and Tk's macOS noTitleBar style. Managed windows preserve task switching
and native minimize/maximize. Keep a Tk fallback when a platform API is absent.
The identity prompt gets a small application-owned header with close only.
Hide the main window until startup finishes, preventing an empty decorated
window behind the prompt. No new packages or service/protocol changes.

Validate native Tk navigation layout, close routing, drag and resize limits,
minimize/restore, maximize/restore, cleanup, and startup cancellation. Inspect
real X11 window properties and full-window screenshots. Native macOS and
Windows behavior remains pending physical validation on those platforms.

References: [Tk window management](https://www.tcl-lang.com/man/tcl8.6/TkCmd/wm.htm),
[Tk macOS window styles](https://raw.githubusercontent.com/tcltk/tk/main/macosx/README),
[Qt XCB window hints](https://github.com/qt/qtbase/blob/dev/src/plugins/platforms/xcb/qxcbwindow.cpp).
