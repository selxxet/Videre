# Videre

Scans your local network and shows all devices in a web interface.

## Setup

Install dependencies:
```bash
pip install -r requirements.txt
```

On Linux you might need: `sudo apt-get install python3-dev libpcap-dev`  
On Mac: `brew install libpcap`

## Usage

Run the app:
```bash
python app.py
```

Then open `http://localhost:5000` in your browser.

Note: On Windows you might need to run as admin. On Linux/Mac use `sudo`.
