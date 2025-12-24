from fastapi import FastAPI, Query
import httpx

app = FastAPI()

@app.get("/")
def root():
    return {"status": "ZeroRisk Sentinel API running"}

@app.get("/status")
async def check_status(url: str = Query(...)):
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            r = await client.head(url)
            return {
                "url": url,
                "status": r.status_code
            }
    except Exception as e:
        return {
            "url": url,
            "status": 0,
            "error": str(e)
        }
