"""Vulnerable FastAPI LLM app — intentionally insecure for testing."""

from fastapi import FastAPI
from pydantic import BaseModel
import openai
import subprocess
import os

app = FastAPI()

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


class ChatRequest(BaseModel):
    message: str
    email: str


@app.post("/chat")
async def chat(req: ChatRequest):
    """User input concatenated directly into LLM prompt — prompt injection surface."""
    # PII logged via print
    print(f"Chat request from {req.email}: {req.message}")

    # User input directly in f-string prompt — prompt injection
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": f"User says: {req.message}. Help them."},
        ],
    )

    result = response.choices[0].message.content

    # LLM output passed to eval — code execution
    eval(result)

    return {"response": result}


@app.post("/execute")
async def execute(req: ChatRequest):
    """LLM output passed to subprocess."""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Generate a bash command for: {req.message}"}],
    )

    cmd = response.choices[0].message.content
    # LLM output to subprocess with shell=True
    subprocess.run(cmd, shell=True)

    return {"executed": cmd}


@app.get("/users")
async def get_users():
    """No auth middleware."""
    return {"users": ["alice", "bob"]}
