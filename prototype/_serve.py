"""Headless server runner for screenshotting (no debug reloader)."""
import app as demo
demo.init_db(force=True)
demo.app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
