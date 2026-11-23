"""
FastAPI Server for SecureMCP Chatbot Web UI & REST API.
"""

from contextlib import asynccontextmanager
from typing import Any, Dict
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mcp_client import SecureMcpClient
from chatbot import SecureMcpChatbot

mcp_client = SecureMcpClient()
chatbot = SecureMcpChatbot(mcp_client)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Attempt initialization on startup
    try:
        chatbot.get_system_status()
    except Exception:
        pass
    yield


app = FastAPI(title="SecureMCP Chatbot Client", lifespan=lifespan)


class ChatRequest(BaseModel):
    message: str


@app.get("/api/status")
def status():
    return chatbot.get_system_status()


@app.get("/api/tools")
def list_tools():
    try:
        tools = mcp_client.list_tools()
        return {"tools": tools}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/chat")
def chat(req: ChatRequest):
    response = chatbot.process_message(req.message)
    return response


@app.get("/", response_class=HTMLResponse)
def index():
    with open("client/templates/index.html", "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=3000, reload=True)
