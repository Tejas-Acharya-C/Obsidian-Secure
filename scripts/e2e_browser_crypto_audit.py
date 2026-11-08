import os, sys, time, json, subprocess, websocket, urllib.request, tempfile

CDP_PORT = 9225
PORT = 8085
BASE_URL = f"http://127.0.0.1:{PORT}"
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

from app import app
import threading
flask_thread = threading.Thread(target=lambda: app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False), daemon=True)
flask_thread.start()
for _ in range(10):
    try:
        r = urllib.request.urlopen(f"{BASE_URL}/")
        print("Flask is alive:", r.status)
        break
    except Exception as e:
        time.sleep(0.5)

user_dir = os.path.join(tempfile.gettempdir(), f"chrome_crypto_{os.getpid()}")
chrome_proc = subprocess.Popen([
    CHROME_PATH,
    "--headless=new",
    "--disable-gpu",
    f"--user-data-dir={user_dir}",
    f"--remote-debugging-port={CDP_PORT}",
    "--remote-allow-origins=*",
    f"--unsafely-treat-insecure-origin-as-secure={BASE_URL}",
    "about:blank"
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2.5)

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
    nav_res = cdp("Page.navigate", {"url": f"{BASE_URL}/"})
    print("Navigation result:", nav_res)
    time.sleep(1.5)

    # 1. Inspect window context
    ctx_res = cdp("Runtime.evaluate", {
        "expression": "JSON.stringify({href: window.location.href, isSecure: window.isSecureContext, hasCrypto: !!window.crypto, hasSubtle: !!(window.crypto && window.crypto.subtle)})",
        "returnByValue": True
    })
    print("Window context:", ctx_res.get("result", {}).get("value"))

    # 1. Verify Web Crypto AES-256-GCM Key Generation, Encryption, Decryption in Chrome
    crypto_test_res = cdp("Runtime.evaluate", {
        "expression": """
        (async function() {
            try {
                // 1. Generate AES-256-GCM Key
                const key = await window.crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                // Export raw key to verify 256-bit (32 bytes)
                const rawKey = await window.crypto.subtle.exportKey('raw', key);
                const keyByteLength = rawKey.byteLength;

                // 2. Encrypt plaintext with 12-byte IV
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const encoder = new TextEncoder();
                const plaintext = encoder.encode('Confidential Web Crypto Test Payload 2026');

                const ciphertextBuffer = await window.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv, tagLength: 128 },
                    key,
                    plaintext
                );

                // 3. Concatenate IV + Ciphertext (standard Obsidian Secure wire format)
                const wireFormat = new Uint8Array(iv.length + ciphertextBuffer.byteLength);
                wireFormat.set(iv, 0);
                wireFormat.set(new Uint8Array(ciphertextBuffer), iv.length);

                // 4. Decrypt from wire format
                const extractedIv = wireFormat.slice(0, 12);
                const extractedCt = wireFormat.slice(12);

                const decryptedBuffer = await window.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: extractedIv, tagLength: 128 },
                    key,
                    extractedCt
                );

                const decoder = new TextDecoder();
                const decryptedText = decoder.decode(decryptedBuffer);
                const decryptSuccess = decryptedText === 'Confidential Web Crypto Test Payload 2026';

                // 5. Test Auth Tag Tampering Rejection
                const tamperedCt = new Uint8Array(extractedCt);
                tamperedCt[tamperedCt.length - 1] ^= 0x01; // flip 1 bit in auth tag
                let tamperRejected = false;
                try {
                    await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: extractedIv, tagLength: 128 },
                        key,
                        tamperedCt
                    );
                } catch(e) {
                    tamperRejected = true;
                }

                // 6. Test URL Fragment Key Parsing
                const exportedRaw = new Uint8Array(rawKey);
                let binaryStr = '';
                for (let i = 0; i < exportedRaw.length; i++) {
                    binaryStr += String.fromCharCode(exportedRaw[i]);
                }
                const b64Key = btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

                // Import back from base64url
                const binaryRoundtrip = atob(b64Key.replace(/-/g, '+').replace(/_/g, '/'));
                const roundtripBytes = new Uint8Array(binaryRoundtrip.length);
                for (let i = 0; i < binaryRoundtrip.length; i++) {
                    roundtripBytes[i] = binaryRoundtrip.charCodeAt(i);
                }
                const importedKey = await window.crypto.subtle.importKey(
                    'raw',
                    roundtripBytes,
                    { name: 'AES-GCM' },
                    true,
                    ['encrypt', 'decrypt']
                );

                const roundtripDecrypted = await window.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: extractedIv, tagLength: 128 },
                    importedKey,
                    extractedCt
                );
                const roundtripSuccess = decoder.decode(roundtripDecrypted) === 'Confidential Web Crypto Test Payload 2026';

                // 7. Check File / Blob / ObjectURL APIs
                const testBlob = new Blob([decryptedBuffer], { type: 'text/plain' });
                const blobUrl = URL.createObjectURL(testBlob);
                const urlValid = blobUrl.startsWith('blob:');
                URL.revokeObjectURL(blobUrl);

                return {
                    success: true,
                    keyByteLength: keyByteLength,
                    is256Bit: keyByteLength === 32,
                    ivLength: iv.length,
                    encryptSuccess: ciphertextBuffer.byteLength > plaintext.length,
                    tagLengthBits: 128,
                    decryptSuccess: decryptSuccess,
                    tamperRejected: tamperRejected,
                    roundtripSuccess: roundtripSuccess,
                    blobApiSupported: urlValid
                };
            } catch (err) {
                return {
                    success: false,
                    error: err.toString()
                };
            }
        })()
        """,
        "awaitPromise": True,
        "returnByValue": True
    })

    val = crypto_test_res.get("result", {}).get("value", {})
    print("\n--- BROWSER WEB CRYPTO IN-ENGINE AUDIT ---")
    print(json.dumps(val, indent=2))

    with open(os.path.join(BASE_DIR, "browser_crypto_audit_results.json"), "w") as f:
        json.dump(val, f, indent=2)

    ws.close()
finally:
    chrome_proc.terminate()
