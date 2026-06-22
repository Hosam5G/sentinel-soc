#!/usr/bin/env python3
"""
Sentinel SOC Launcher — Windows desktop app entry point.

Starts the Flask server in a background thread, opens the browser,
and optionally adds a system tray icon. Designed for PyInstaller bundling.

Usage:
    python launcher.py                  # run locally
    pyinstaller --onefile launcher.py   # bundle into .exe
"""
import os
import sys
import time
import threading
import webbrowser
import socket

# Ensure the dashboard module can be imported.
# Under PyInstaller (--onefile) data files are extracted to sys._MEIPASS.
_HERE = os.path.dirname(os.path.abspath(__file__))
_BUNDLE = getattr(sys, "_MEIPASS", None)
sys.path.insert(0, _HERE)
if _BUNDLE:
    sys.path.insert(0, _BUNDLE)
    # point the server at the bundled dashboard/ if the user didn't override
    bundled_dash = os.path.join(_BUNDLE, "dashboard")
    if os.path.isdir(bundled_dash):
        os.environ.setdefault("SENTINEL_DASHBOARD_DIR", bundled_dash)
else:
    local_dash = os.path.join(_HERE, "dashboard")
    if os.path.isdir(local_dash):
        os.environ.setdefault("SENTINEL_DASHBOARD_DIR", local_dash)

try:
    import dashboard_routes as app_module
except ImportError as e:
    print(f"Error: could not import dashboard_routes: {e}")
    sys.exit(1)


def find_free_port(start=8000, end=9000):
    """Find a free port in the given range."""
    for port in range(start, end):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", port))
            s.close()
            return port
        except OSError:
            continue
    return start


def run_server(app, port):
    """Run the Flask server in a thread-safe way."""
    try:
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except Exception as e:
        print(f"Server error: {e}")


def main():
    """Main entry point for the desktop app."""
    port = find_free_port()
    url = f"http://127.0.0.1:{port}"
    
    # Create the Flask app
    app = app_module.create_app()
    
    # Start the server in a background daemon thread
    server_thread = threading.Thread(target=run_server, args=(app, port), daemon=True)
    server_thread.start()
    
    # Give the server a moment to start
    time.sleep(2)
    
    # Open the default browser
    print(f"🚀 Sentinel SOC starting at {url}")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"⚠ Could not open browser: {e}")
        print(f"   Please open {url} manually in your browser.")
    
    # Optional: try to add a system tray icon (Windows-specific).
    # ANY failure here must NOT crash the app — the server is what matters.
    tray_ok = False
    try:
        import pystray
        from PIL import Image, ImageDraw

        def create_icon_image():
            """Draw a simple shield icon (no font dependency)."""
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.polygon([(32, 4), (58, 14), (58, 34), (32, 60), (6, 34), (6, 14)],
                      fill=(34, 139, 84, 255), outline=(20, 90, 54, 255))
            d.line([(20, 32), (29, 42), (46, 21)], fill=(255, 255, 255, 255), width=5)
            return img

        def on_exit(icon, item):
            icon.stop()
            os._exit(0)

        def on_open(icon, item):
            webbrowser.open(url)

        # build the menu defensively: SEPARATOR exists on pystray.Menu in current
        # versions, but guard against API differences so a bad pystray build can
        # never crash the launcher.
        menu_items = [pystray.MenuItem("Open Sentinel", on_open, default=True)]
        sep = getattr(pystray.Menu, "SEPARATOR", None)
        if sep is not None:
            menu_items.append(sep)
        menu_items.append(pystray.MenuItem("Exit", on_exit))

        icon = pystray.Icon(
            name="Sentinel SOC",
            icon=create_icon_image(),
            title="Sentinel SOC",
            menu=pystray.Menu(*menu_items),
        )
        print("📌 Sentinel SOC is running. Look for the icon in your system tray.")
        tray_ok = True
        icon.run()
    except Exception as e:
        # pystray missing OR any tray error — keep the server running regardless.
        print(f"ℹ  Running without tray icon ({type(e).__name__}). "
              f"Sentinel is still active at {url}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n👋 Sentinel SOC stopped.")
            os._exit(0)


if __name__ == "__main__":
    main()
