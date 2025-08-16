from fastapi import FastAPI
import os
app = FastAPI()
@app.get("/healthz")
def health():
    return {"ok": True, "openai_key_set": bool(os.environ.get("OPENAI_API_KEY"))}
