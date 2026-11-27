# NovaPay FinTech — Standalone Demo Target App for MIRAGE Shield

NovaPay is an independent demo customer web application wrapped with the **MIRAGE Shield** middleware (`demo_target/shield_sdk.py`) for college presentations and customer demonstrations.

## Run Locally
Starts automatically alongside MIRAGE Shield when running `python main.py` (port `5050`), or start standalone:

```bash
python demo_target/app.py
```

Open `http://localhost:5050`.

## Deploy as a 2nd Independent Website on Vercel
1. Open Vercel Dashboard &rarr; **Add New Project** &rarr; select `Jaskaranbandral-07/mirage-junior`.
2. Set **Root Directory** to `demo_target`.
3. Optional Environment Variables:
   - `MIRAGE_SHIELD_URL` = `https://mirage-junior.vercel.app` (default when on Vercel)
4. Click **Deploy**. Copy the new URL (e.g. `https://novapay-demo.vercel.app`) and paste it into MIRAGE Shield &rarr; **Get Extension / Demo Website Setup** (or set `DEMO_TARGET_URL` on the main project).
