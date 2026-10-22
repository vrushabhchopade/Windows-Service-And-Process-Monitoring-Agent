import os
import sys
import subprocess
import time
from pathlib import Path

def main():
    root_dir = Path(__file__).resolve().parent
    backend_dir = root_dir / "backend"
    
    print("=================================================================")
    # ASCII Art
    print("  ___ _   _ _        _      ___            _   _                 _ ")
    print(" / __| |_(_) |_  ___| |_   / __| ___ _ __ | |_(_)_ _  ___ _  ___| |")
    print(" \\__ \\  _| |  _|/ __| ' \\  \\__ \\/ -_) '  \\|  _| | ' \\/ -_) |/ -_) |")
    print(" |___/\\__|_|\\__|\\___|_||_| |___/\\___|_|_|_|\\__|_|_||_\\___|_|\\___|_|")
    print("                                                                   ")
    print("           Windows Service & Process Monitoring Agent EDR          ")
    print("=================================================================")

    # Create logs directory if not exists
    (root_dir / "logs").mkdir(exist_ok=True)

    # Run Database Migrations
    print("[*] Running Django migrations...")
    subprocess.run([sys.executable, str(backend_dir / "manage.py"), "migrate"], cwd=str(backend_dir))

    # Run Database Seeding
    print("[*] Seeding default database metrics...")
    subprocess.run([sys.executable, str(backend_dir / "manage.py"), "seed_data"], cwd=str(backend_dir))

    # Run Django Test Server
    print("[*] Launching SOC Dashboard on http://127.0.0.1:8000 ...")
    web_process = subprocess.Popen([sys.executable, str(backend_dir / "manage.py"), "runserver", "127.0.0.1:8000"], cwd=str(backend_dir))

    # Wait for Django to boot up
    time.sleep(2)

    # Run Agent in background or once to collect initial local telemetry
    print("[*] Launching EDR Agent to audit local systems...")
    agent_process = subprocess.Popen([sys.executable, str(root_dir / "agent" / "main.py")], cwd=str(root_dir))

    print("\n[+] Both systems running successfully.")
    print("[*] Access Dashboard: http://127.0.0.1:8000/ (admin / admin123)")
    print("[*] Press Ctrl+C to terminate both processes.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down services...")
        web_process.terminate()
        agent_process.terminate()
        print("[+] Done.")

if __name__ == "__main__":
    main()
