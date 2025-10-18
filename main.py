from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

# === CONFIG ===
MODEL_NAME = "microsoft/phi-2"  # For Free Tier. Use better models for Pro/Ultimate.

# === INIT ===
app = FastAPI(title="FreeAI - Billy (Phi-2)")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
)
model.eval()

# === CORS (so frontend & PWA can call it) ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your frontend domain in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Request Schema ===
class ChatRequest(BaseModel):
    model: str = "free"
    messages: list

# === Helper: Format as Chat History ===
def format_prompt(messages):
    prompt = "You are Billy, a helpful and friendly assistant.\n\n"
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if role == "user":
            prompt += f"User: {content}\n"
        elif role == "assistant":
            prompt += f"Billy: {content}\n"
    prompt += "Billy:"
    return prompt

# === /chat Endpoint (Main Chat API) ===
@app.post("/chat")
async def chat(req: ChatRequest):
    prompt = format_prompt(req.messages)

    inputs = tokenizer(prompt, return_tensors="pt", truncation=True).to(model.device)

    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=150,  # Limit for Free Tier
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            pad_token_id=tokenizer.eos_token_id
        )

    decoded = tokenizer.decode(output[0], skip_special_tokens=True)
    response = decoded.split("Billy:")[-1].strip()

    return {"message": {"content": response}}
