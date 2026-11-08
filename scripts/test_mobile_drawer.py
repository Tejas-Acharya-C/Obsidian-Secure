import os, sys, time, json, subprocess, websocket, urllib.request

CDP_PORT = 9224
PORT = 5059
BASE_URL = f"http://127.0.0.1:{PORT}"
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

# Start Flask
from app import app
import threading
flask_thread = threading.Thread(target=lambda: app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False), daemon=True)
flask_thread.start()
time.sleep(1.5)

chrome_proc = subprocess.Popen([
    CHROME_PATH,
    "--headless=new",
    "--disable-gpu",
    f"--remote-debugging-port={CDP_PORT}",
    "--remote-allow-origins=*",
    "about:blank"
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)

_id = 0

try:
    tabs = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json").read().decode())
    ws = websocket.create_connection(tabs[0]["webSocketDebuggerUrl"])
    def cdp(method, params=None):
        global _id
        _id += 1
        msg = {"id": _id, "method": method}
        if params: msg["params"] = params
        ws.send(json.dumps(msg))
        while True:
            r = json.loads(ws.recv())
            if r.get("id") == _id: return r.get("result", {})

    cdp("Page.enable")
    cdp("Runtime.enable")
    cdp("Emulation.setDeviceMetricsOverride", {"width": 375, "height": 667, "deviceScaleFactor": 1, "mobile": True})
    cdp("Page.navigate", {"url": f"{BASE_URL}/"})
    time.sleep(1)

    # 1. Inspect hamburger button visibility and dimensions
    res1 = cdp("Runtime.evaluate", {
        "expression": """
        (function() {
            var btn = document.getElementById('mobileNavToggle') || document.querySelector('[data-mobile-nav-toggle]') || document.querySelector('button[aria-label*="navigation" i]') || document.querySelector('header button');
            if (!btn) return { found: false };
            var rect = btn.getBoundingClientRect();
            var cs = window.getComputedStyle(btn);
            return {
                found: true,
                id: btn.id,
                width: rect.width,
                height: rect.height,
                ariaExpanded: btn.getAttribute('aria-expanded'),
                display: cs.display,
                visibility: cs.visibility
            };
        })()
        """,
        "returnByValue": True
    })
    btn_metrics = res1.get("result", {}).get("value", {})
    print("Hamburger button metrics:", btn_metrics)

    # 2. Click hamburger button to open drawer
    res2 = cdp("Runtime.evaluate", {
        "expression": """
        (function() {
            var btn = document.getElementById('mobile-nav-toggle');
            if (!btn) return { error: 'no btn' };
            btn.click();
            var panel = document.getElementById('mobile-nav-panel');
            var overlay = document.getElementById('mobile-nav-backdrop');
            return {
                panelActive: panel ? panel.classList.contains('active') : false,
                backdropActive: overlay ? overlay.classList.contains('active') : false,
                ariaExpanded: btn.getAttribute('aria-expanded'),
                bodyHasNoScroll: document.body.classList.contains('no-scroll'),
                panelDisplay: panel ? window.getComputedStyle(panel).display : 'none'
            };
        })()
        """,
        "returnByValue": True
    })
    open_res = res2.get("result", {}).get("value", {})
    print("Drawer Open State:", open_res)

    # 3. Check touch targets inside open drawer
    res3 = cdp("Runtime.evaluate", {
        "expression": """
        (function() {
            var panel = document.getElementById('mobile-nav-panel');
            if (!panel) return [];
            var items = panel.querySelectorAll('a, button');
            var results = [];
            items.forEach(function(el) {
                var r = el.getBoundingClientRect();
                results.push({
                    text: el.innerText.trim(),
                    tag: el.tagName,
                    width: Math.round(r.width),
                    height: Math.round(r.height),
                    adequate: r.height >= 44
                });
            });
            return results;
        })()
        """,
        "returnByValue": True
    })
    touch_targets = res3.get("result", {}).get("value", [])
    print("Drawer touch target dimensions:", touch_targets)

    # 4. Press Escape to test keyboard dismissal & focus restoration
    res4 = cdp("Runtime.evaluate", {
        "expression": """
        (function() {
            var evt = new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true });
            document.dispatchEvent(evt);
            var panel = document.getElementById('mobile-nav-panel');
            var btn = document.getElementById('mobile-nav-toggle');
            var overlay = document.getElementById('mobile-nav-backdrop');
            return {
                panelActive: panel ? panel.classList.contains('active') : true,
                backdropActive: overlay ? overlay.classList.contains('active') : true,
                ariaExpanded: btn ? btn.getAttribute('aria-expanded') : '',
                bodyHasNoScroll: document.body.classList.contains('no-scroll'),
                focusReturned: document.activeElement === btn
            };
        })()
        """,
        "returnByValue": True
    })
    esc_res = res4.get("result", {}).get("value", {})
    print("Escape key dismissal:", esc_res)

    ws.close()
finally:
    chrome_proc.terminate()
