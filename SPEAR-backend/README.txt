S.P.E.A.R BACKEND
=================

Requirements
- Python 3.10 or newer (no external packages required)
- Windows, macOS, or Linux

Run on Windows
1. Extract this ZIP to a folder.
2. Double-click Run-Backend.bat and keep its window open.
   Or open PowerShell here and run: py -3 server.py
3. The local backend listens at http://127.0.0.1:8000.

Run the separate frontend
1. Extract the S.P.E.A.R-frontend.zip to a folder.
2. Open a second PowerShell window in the extracted frontend folder.
3. Run: py -3 -m http.server 5500 --bind 127.0.0.1
4. In your browser, open http://127.0.0.1:5500.

The API is limited to loopback. Uploaded .eml files are parsed in memory; the
original upload is not saved. Analysis summaries are stored in
spear_history.sqlite3 beside server.py. Stop the backend with Ctrl+C.

The analyzer reads message headers, Authentication-Results text, readable
message-body links, attachment names/types, and a short list of urgency phrases.
It does not query DNS, verify DKIM signatures, open links, run attachments, or
scan for malware. Its score is only a heuristic for educational demonstration.

API endpoints
GET  /api/health
POST /api/analyze       multipart/form-data field "file", .eml up to 5 MB
POST /api/ask           JSON {"question":"...", "report":{...}} offline spoofing guide
GET  /api/history       latest 100 saved reports (summary fields)
POST /api/history/clear clear local history

The top-right AI Guide is an offline, rule-based educational helper, not a
generative AI service. It can explain common email spoofing concepts and the
latest report. It does not verify messages, query external services, or certify
that an email is safe. No question or report is sent outside this computer.
