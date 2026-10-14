S.P.E.A.R FRONTEND
==================

This is the separate browser interface. It requires the S.P.E.A.R backend ZIP
to be running at http://127.0.0.1:8000.

Run on Windows
1. Extract this ZIP to a folder.
2. Double-click Run-Website.bat. It opens http://127.0.0.1:5500.
   Or open PowerShell here and run: py -3 -m http.server 5500 --bind 127.0.0.1

Start the backend in another PowerShell window using the instructions in its
README.txt. The status indicator at the top should say “Backend connected”.

No frontend packages or build step are required. The site background and
decorative security illustration are part of the interface. The backend only
runs while its terminal window remains open. Email analysis and history are
available only while the backend is running.
