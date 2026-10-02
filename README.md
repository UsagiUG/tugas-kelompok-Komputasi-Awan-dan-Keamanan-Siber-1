# Cara akses cloud run (google)
```powershell
python main.py --url "https://hybrid-crypto-1000486494243.asia-southeast2.run.app/telemetry/"
```
# Cara run project lokal
1. From root, install Python requirements: requirements.txt (example: pip install -r requirements.txt)
2. Run generate_key.py to generate server's RSA and ECC key pairs (example: python generate_key.py)
3. Change working directory to backend (PowerShell example: cd backend)
4. Install Node.js requirements: npm install
5. Run server: npm start
6. Open new terminal, change working directory to frontend (PowerShell example from root: cd frontend)
7. Run main.py (example: python main.py)
