# Extension

Load this folder as an unpacked extension in Chrome:
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select this `extension/` folder
4. Open Gmail or any regular webpage
5. Click the extension icon and set **Backend API base URL** if needed
6. The extension auto-analyzes when a new email/page is opened
7. You can still manually click **Analyze current page**
8. When a regular webpage is rated **medium** or **high**, a Chrome notification is shown

By default backend URL is `http://127.0.0.1:5000` with fallback to `http://localhost:5000`.
