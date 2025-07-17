import express from "express";
import cors from "cors";
import { HfInference } from "@huggingface/inference";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const hf = new HfInference(process.env.HF_API_KEY);

app.post("/chat", async (req, res) => {
  const prompt = req.body.prompt;
  if (!prompt) return res.status(400).json({ error: "Missing prompt" });

  try {
    const result = await hf.textGeneration({
      model: "microsoft/phi-2",
      inputs: prompt,
      parameters: {
        max_new_tokens: 300,
        return_full_text: false
      }
    });
    res.json({ response: result.generated_text });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Inference failed" });
  }
});

app.get("/", (req, res) => {
  res.send("🧠 Phi-4 API is running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Running on port ${PORT}`));
