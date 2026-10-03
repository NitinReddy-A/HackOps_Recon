# LLMs & API keys — what to use and how to connect (free options first)

Rampart's reasoning layer is **advisory only** — it proposes hypotheses, drafts prose, and
suggests patches, but the deterministic engine and the independent validator decide what is
real. That means the model choice affects *quality of suggestions*, not *safety* or *whether
findings are trustworthy*. You can therefore start with the free default and add a key later.

> Prices, free tiers, and model names in this space change within weeks. Treat the specifics
> below as a starting map and verify against each provider's current docs before you rely on them.

## The three modes

| `--intel` | Backend | Key needed | Cost | Best for |
|---|---|---|---|---|
| `deterministic` *(default)* | built-in rules | none | **$0** | CI, offline, reproducible runs, getting started |
| `claude-code` | your local `claude` CLI | no separate API key (uses your Claude Code plan) | your plan | highest-quality reasoning with zero key setup |
| `openai-compat` | any OpenAI-compatible HTTP API | yes (yours) | your provider's rates | bringing your own model/provider |

Rampart makes only a handful of LLM calls per engagement (hypotheses + narrative + optional
patch ≈ 2–4 calls), so even on a paid model an assessment typically costs **cents**. High-volume
CI can pin a small/cheap model; deep runs can use a frontier model.

## Free options for initial testing

1. **Ollama — fully local, free, private (recommended for self-hosters).**
   Nothing leaves your machine. Good models: `qwen2.5`, `llama3.1`, `mistral`.
   ```bash
   # install Ollama, then:
   ollama pull qwen2.5
   export RAMPART_LLM_BASE_URL="http://localhost:11434/v1"
   export RAMPART_LLM_MODEL="qwen2.5"
   export RAMPART_LLM_API_KEY="ollama"     # any non-empty string
   python -m rampart test --intel openai-compat ...
   ```

2. **Groq — free tier, very fast.** OpenAI-compatible.
   ```bash
   export RAMPART_LLM_BASE_URL="https://api.groq.com/openai/v1"
   export RAMPART_LLM_MODEL="llama-3.3-70b-versatile"
   export RAMPART_LLM_API_KEY="gsk_..."     # from console.groq.com
   python -m rampart test --intel openai-compat ...
   ```

3. **OpenRouter — many models, several with a `:free` tier.** OpenAI-compatible; one key, many models.
   ```bash
   export RAMPART_LLM_BASE_URL="https://openrouter.ai/api/v1"
   export RAMPART_LLM_MODEL="meta-llama/llama-3.3-70b-instruct:free"   # check current free list
   export RAMPART_LLM_API_KEY="sk-or-..."
   python -m rampart test --intel openai-compat ...
   ```

4. **Google AI Studio (Gemini)** and **most providers** offer a free trial/credit for evaluation —
   check each provider. Any that exposes an OpenAI-compatible endpoint works via `openai-compat`;
   otherwise put a **LiteLLM gateway** in front (below).

5. **Claude Code** — if you already use it, `--intel claude-code` needs no API key at all.

## Paid / production models

- **Frontier hosted** (best reasoning): Anthropic Claude, OpenAI GPT, Google Gemini. Use for deep runs.
- **Open-weight, near-frontier coding** you can self-host: Qwen3, Kimi, gpt-oss, DeepSeek — run them
  under **vLLM** (throughput) or **Ollama** (ease) and point `RAMPART_LLM_BASE_URL` at them. This keeps
  code and targets fully in your infra — the whole reason Rampart is self-hostable.

## One gateway for everything (recommended for teams): LiteLLM

Run a self-hosted [LiteLLM](https://github.com/BerriAI/litellm) proxy and point Rampart at it once.
You then manage providers, virtual keys, budgets, fallbacks, and cost tracking centrally:
```bash
export RAMPART_LLM_BASE_URL="http://localhost:4000/v1"
export RAMPART_LLM_MODEL="your-alias"
export RAMPART_LLM_API_KEY="sk-litellm-..."
python -m rampart test --intel openai-compat ...
```

## Configuration reference

| Env var | Default | Meaning |
|---|---|---|
| `RAMPART_LLM_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL |
| `RAMPART_LLM_MODEL` | `gpt-4o-mini` | model id |
| `RAMPART_LLM_API_KEY` | — | the key itself (highest precedence) |
| `RAMPART_LLM_API_KEY_ENV` | `OPENAI_API_KEY` | name of the env var holding the key (if not using `RAMPART_LLM_API_KEY`) |

## Privacy

Self-hosting is the point. For maximum privacy use **Ollama/vLLM (local weights)** or a
**self-hosted LiteLLM gateway**, so prompts (which may contain snippets of your app model) never
leave your network. If you use a hosted provider, review its data-retention / zero-data-retention
policy. Rampart redacts secrets before anything is logged or sent, and target-derived text is
always passed to the model as clearly-delimited *untrusted data*, never as instructions.
