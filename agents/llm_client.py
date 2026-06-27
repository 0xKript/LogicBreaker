"""
Multi-provider LLM client
=========================

A single interface over the major LLM APIs. The user picks a provider at
startup (or runs with no provider at all -- "fast scan" mode, fully heuristic).

Each provider entry defines its endpoint, auth header style, and request/
response shape, so adding a new provider is a one-line dict entry.

The client is used only for *optional* triage/enrichment and suggested fixes.
The core detection + dynamic exploitation + verified patching does not depend
on it, so "fast scan" mode is fully functional.
"""

import ast
import hashlib
import json
import os
import re
import tempfile

import requests


def _parse_json_lenient(raw):
    """Parse a model's JSON reply ROBUSTLY (FIX A, determinism).

    Models occasionally wrap the JSON in prose/markdown, add a trailing comma, or
    emit Python-style quoting. A brittle json.loads would drop an otherwise-valid
    verdict; because a dropped verdict used to go UNCACHED, the next run (which
    parsed cleanly) would relabel the finding -- the exact run-to-run drift FIX A
    targets. We try progressively more tolerant parses and only give up if none
    yields an object. Pure function of `raw`, so it is itself deterministic."""
    if raw is None:
        raise ValueError("empty LLM response")
    cleaned = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    candidates = [cleaned]
    m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if m and m.group(0) != cleaned:
        candidates.append(m.group(0))
    for cand in candidates:
        # 1) strict JSON
        try:
            return json.loads(cand)
        except Exception:
            pass
        # 2) JSON with trailing commas removed
        try:
            return json.loads(re.sub(r",(\s*[}\]])", r"\1", cand))
        except Exception:
            pass
        # 3) Python-literal fallback (single quotes / True/False/None)
        try:
            v = ast.literal_eval(cand)
            if isinstance(v, dict):
                return v
        except Exception:
            pass
    raise ValueError("LLM response was not parseable as a JSON object")


PROVIDERS = {
    "claude": {
        "label": "Anthropic Claude  (claude-sonnet-4-5 / opus)",
        "env": "ANTHROPIC_API_KEY",
        "url": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-sonnet-4-5",
        "style": "anthropic",
        "key_hint": "sk-ant-...",
    },
    "openai": {
        "label": "OpenAI  (gpt-4o / gpt-4.1)",
        "env": "OPENAI_API_KEY",
        "url": "https://api.openai.com/v1/chat/completions",
        "default_model": "gpt-4o",
        "style": "openai",
        "key_hint": "sk-...",
    },
    "gemini": {
        "label": "Google Gemini  (gemini-2.0-flash / 1.5-pro)",
        "env": "GEMINI_API_KEY",
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "default_model": "gemini-2.0-flash",
        "style": "gemini",
        "key_hint": "AIza...",
    },
    "groq": {
        "label": "Groq  (llama-3.3-70b, very fast)",
        "env": "GROQ_API_KEY",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "default_model": "llama-3.3-70b-versatile",
        "style": "openai",
        "key_hint": "gsk_...",
    },
    "mistral": {
        "label": "Mistral AI  (mistral-large)",
        "env": "MISTRAL_API_KEY",
        "url": "https://api.mistral.ai/v1/chat/completions",
        "default_model": "mistral-large-latest",
        "style": "openai",
        "key_hint": "...",
    },
    "deepseek": {
        "label": "DeepSeek  (deepseek-chat)",
        "env": "DEEPSEEK_API_KEY",
        "url": "https://api.deepseek.com/chat/completions",
        "default_model": "deepseek-chat",
        "style": "openai",
        "key_hint": "sk-...",
    },
    "together": {
        "label": "Together AI  (Llama / Qwen / Mixtral)",
        "env": "TOGETHER_API_KEY",
        "url": "https://api.together.xyz/v1/chat/completions",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "style": "openai",
        "key_hint": "...",
    },
    "openrouter": {
        "label": "OpenRouter  (gateway to 100+ models)",
        "env": "OPENROUTER_API_KEY",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "default_model": "anthropic/claude-3.5-sonnet",
        "style": "openai",
        "key_hint": "sk-or-...",
    },
    "xai": {
        "label": "xAI Grok  (grok-2)",
        "env": "XAI_API_KEY",
        "url": "https://api.x.ai/v1/chat/completions",
        "default_model": "grok-2-latest",
        "style": "openai",
        "key_hint": "xai-...",
    },
    "cohere": {
        "label": "Cohere  (command-r-plus)",
        "env": "COHERE_API_KEY",
        "url": "https://api.cohere.com/v2/chat",
        "default_model": "command-r-plus",
        "style": "openai",
        "key_hint": "...",
    },
    "perplexity": {
        "label": "Perplexity  (sonar-pro, web-grounded)",
        "env": "PERPLEXITY_API_KEY",
        "url": "https://api.perplexity.ai/chat/completions",
        "default_model": "sonar-pro",
        "style": "openai",
        "key_hint": "pplx-...",
    },
    "fireworks": {
        "label": "Fireworks AI  (Llama / Qwen / DeepSeek, fast)",
        "env": "FIREWORKS_API_KEY",
        "url": "https://api.fireworks.ai/inference/v1/chat/completions",
        "default_model": "accounts/fireworks/models/llama-v3p3-70b-instruct",
        "style": "openai",
        "key_hint": "fw_...",
    },
    "cerebras": {
        "label": "Cerebras  (llama-3.3-70b, fastest inference)",
        "env": "CEREBRAS_API_KEY",
        "url": "https://api.cerebras.ai/v1/chat/completions",
        "default_model": "llama-3.3-70b",
        "style": "openai",
        "key_hint": "csk-...",
    },
    "sambanova": {
        "label": "SambaNova  (Llama 3.3 70B / 405B)",
        "env": "SAMBANOVA_API_KEY",
        "url": "https://api.sambanova.ai/v1/chat/completions",
        "default_model": "Meta-Llama-3.3-70B-Instruct",
        "style": "openai",
        "key_hint": "...",
    },
    "nebius": {
        "label": "Nebius AI Studio  (Llama / Qwen / DeepSeek)",
        "env": "NEBIUS_API_KEY",
        "url": "https://api.studio.nebius.com/v1/chat/completions",
        "default_model": "meta-llama/Llama-3.3-70B-Instruct",
        "style": "openai",
        "key_hint": "...",
    },
}

MENU_ORDER = ["claude", "openai", "gemini", "groq", "mistral",
              "deepseek", "together", "openrouter", "xai", "cohere",
              "perplexity", "fireworks", "cerebras", "sambanova", "nebius"]


class LLMClient:
    def __init__(self, provider=None, api_key=None, model=None):
        self.provider = provider
        self.spec = PROVIDERS.get(provider) if provider else None
        self.api_key = api_key or (os.environ.get(self.spec["env"]) if self.spec else None)
        self.model = model or (self.spec["default_model"] if self.spec else None)

    @property
    def available(self) -> bool:
        return bool(self.spec and self.api_key)

    def validate_key(self, timeout=20.0):
        """
        Really verify the API key works with the selected provider's model by
        sending a tiny test request. Returns (ok: bool, message: str).

        This catches: empty keys, malformed keys, random text, and keys for the
        wrong provider -- the provider itself rejects them (401/403), so we
        report a clear error instead of silently 'accepting' a bad key.

        CRITICAL: this method BYPASSES the cache entirely. If we used the cache,
        a previous valid key's response would make an invalid key appear valid.
        """
        if not self.spec:
            return False, "No provider selected."
        if not self.api_key or not self.api_key.strip():
            return False, "No API key provided."

        key = self.api_key.strip()
        # cheap format sanity check per provider (catches obvious typos / Enter)
        fmt_ok, fmt_msg = self._key_format_ok(key)
        if not fmt_ok:
            return False, fmt_msg

        # live check: one minimal request. BYPASS THE CACHE so we actually
        # contact the provider and verify THIS key (not a cached response from
        # a previous key). Any non-auth error (e.g. rate limit) still means
        # the key itself is valid.
        old_cache_setting = os.environ.get("LB_NO_LLM_CACHE", "")
        os.environ["LB_NO_LLM_CACHE"] = "1"
        try:
            self.chat("You are a test.", "Reply with: ok", max_tokens=5, timeout=timeout)
            return True, f"API key verified — {self.provider} ({self.model}) is reachable."
        except RuntimeError as e:
            msg = str(e).lower()
            # ONLY treat as auth failure if the error is SPECIFICALLY about
            # authentication (not just any error containing "invalid")
            if "401" in msg or "403" in msg or "unauthor" in msg \
               or "api key" in msg or "authentication" in msg \
               or "invalid api key" in msg or "invalid x-api-key" in msg \
               or "permission denied" in msg or "forbidden" in msg:
                return False, (f"The API key was rejected by {self.provider} "
                               f"(authentication failed). Check the key is correct and is for "
                               f"{self.provider}.")
            if "429" in msg or "rate" in msg or "quota" in msg or "billing" in msg \
               or "insufficient" in msg:
                # key is valid, just rate-limited / out of credit
                return True, (f"API key is valid for {self.provider}, but the account is rate-limited "
                              f"or out of credit. Scanning can proceed; LLM triage may be limited.")
            if "404" in msg or ("model" in msg and "not found" in msg):
                return False, (f"The key may be valid but model '{self.model}' was not found for "
                               f"{self.provider}. Try a different model.")
            # network / unknown -> report it so the user isn't misled
            return False, f"Could not verify the key with {self.provider}: {str(e)[:160]}"
        except Exception as e:
            return False, f"Could not reach {self.provider}: {str(e)[:160]}"
        finally:
            # restore the original cache setting
            if old_cache_setting:
                os.environ["LB_NO_LLM_CACHE"] = old_cache_setting
            else:
                os.environ.pop("LB_NO_LLM_CACHE", None)

    def _key_format_ok(self, key):
        """Per-provider format check to reject obvious garbage before a network
        call. Conservative: only rejects clearly-wrong shapes.

        We do NOT reject keys based on prefix alone for providers whose key
        formats vary. The real validation is the live API request in
        validate_key() -- this is just a quick sanity check."""
        # universal: must not contain spaces, must be a reasonable length
        if " " in key or "\t" in key:
            return False, "API key contains spaces — that is not a valid key."
        if len(key) < 12:
            return False, "API key is too short to be valid."
        # Only check prefix for providers with a VERY strict, well-known format.
        # For providers with varied formats, skip the prefix check and let the
        # live API request decide.
        strict_prefix = {
            "groq": ("gsk_",),
            "xai": ("xai-",),
            "perplexity": ("pplx-",),
            "fireworks": ("fw_",),
            "cerebras": ("csk-",),
        }.get(self.provider, ())
        if strict_prefix and not any(key.startswith(p) for p in strict_prefix):
            return False, (f"This does not look like a {self.provider} API key "
                           f"(expected it to start with {' or '.join(strict_prefix)}).")
        return True, ""

    def chat(self, system_prompt, user_prompt, temperature=0.0, max_tokens=1024, timeout=45.0):
        # DETERMINISM: default temperature is 0.0. Classification, triage, the
        # safety net and the verdict must be reproducible -- the same code must
        # yield the same result on every run. There is no reason to sample here.
        if not self.available:
            raise RuntimeError("No LLM provider configured")

        #  content-hash cache for deterministic calls. A temperature-0 call
        # on the same (system, user, max_tokens) inputs yields the same reply,
        # so caching is sound and saves cost+time on re-runs of unchanged files.
        # The cache is on disk so it survives across runs. Disable with
        # LB_NO_LLM_CACHE=1.
        cache_disabled = os.environ.get("LB_NO_LLM_CACHE", "") in ("1", "true", "True")
        cache_key = None
        if not cache_disabled and temperature == 0.0:
            cache_key = self._cache_key(system_prompt, user_prompt, max_tokens)
            cached = self._cache_get(cache_key)
            if cached is not None:
                return cached

        style = self.spec["style"]
        if style == "anthropic":
            result = self._anthropic(system_prompt, user_prompt, temperature, max_tokens, timeout)
        elif style == "gemini":
            result = self._gemini(system_prompt, user_prompt, temperature, max_tokens, timeout)
        else:
            result = self._openai(system_prompt, user_prompt, temperature, max_tokens, timeout)

        if cache_key is not None:
            self._cache_put(cache_key, result)
        return result

    def chat_json(self, system_prompt, user_prompt, **kwargs):
        # JSON/analysis calls are ALWAYS deterministic, regardless of any future
        # change to chat()'s default: force temperature 0 unless explicitly set.
        kwargs.setdefault("temperature", 0.0)
        raw = self.chat(system_prompt, user_prompt, **kwargs)
        # Robust, deterministic parse (handles fences / prose / trailing commas /
        # single-quoted output). Raises ValueError if nothing parses.
        return _parse_json_lenient(raw)

    # ----  disk cache for deterministic LLM calls ----------------------

    def _cache_key(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
        """Stable content-hash key for a deterministic call.

        Includes a hash of the API key so that changing the key invalidates
        the cache (a different key must never return a cached response from
        a previous key)."""
        key_hash = hashlib.sha256(self.api_key.encode("utf-8", "replace")).hexdigest()[:16] if self.api_key else "no-key"
        raw = f"{self.provider}|{self.model}|{max_tokens}|{key_hash}|{system_prompt}|{user_prompt}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()

    def _cache_dir(self) -> str:
        d = os.path.expanduser(
            os.environ.get("LB_CACHE_DIR", "~/.logicbreaker/cache"))
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            d = os.path.join(tempfile.gettempdir(), "logicbreaker_cache")
            os.makedirs(d, exist_ok=True)
        return d

    def _cache_get(self, key: str):
        path = os.path.join(self._cache_dir(), f"{key}.txt")
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            return None

    def _cache_put(self, key: str, value: str):
        path = os.path.join(self._cache_dir(), f"{key}.txt")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(value)
        except OSError:
            pass  # cache is best-effort; never fail a call because of it

    def _redact(self, text):
        """Belt-and-suspenders: never let the API key surface in an error string,
        log line, or anything we raise/print. Shows only the last 4 chars."""
        text = text or ""
        if self.api_key and self.api_key in text:
            text = text.replace(self.api_key, "****" + self.api_key[-4:])
        return text

    def _openai(self, system, user, temperature, max_tokens, timeout):
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": temperature, "max_tokens": max_tokens,
        }
        r = requests.post(self.spec["url"], headers=headers, json=body, timeout=timeout)
        if r.status_code != 200:
            raise RuntimeError(self._redact(f"{self.provider} error {r.status_code}: {r.text[:300]}"))
        return r.json()["choices"][0]["message"]["content"]

    def _anthropic(self, system, user, temperature, max_tokens, timeout):
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        body = {
            "model": self.model, "max_tokens": max_tokens, "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        r = requests.post(self.spec["url"], headers=headers, json=body, timeout=timeout)
        if r.status_code != 200:
            raise RuntimeError(self._redact(f"claude error {r.status_code}: {r.text[:300]}"))
        data = r.json()
        return "".join(block.get("text", "") for block in data.get("content", []))

    def _gemini(self, system, user, temperature, max_tokens, timeout):
        # SECURITY: pass the key in a HEADER, never as a `?key=` URL query param,
        # so it cannot leak into an exception string, a proxy/access log, or
        # terminal output if the request fails or is traced.
        url = self.spec["url"].format(model=self.model)
        headers = {"Content-Type": "application/json", "x-goog-api-key": self.api_key}
        body = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": user}]}],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        r = requests.post(url, headers=headers, json=body, timeout=timeout)
        if r.status_code != 200:
            raise RuntimeError(self._redact(f"gemini error {r.status_code}: {r.text[:300]}"))
        data = r.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]


def provider_menu():
    return [(k, PROVIDERS[k]["label"], PROVIDERS[k]["key_hint"]) for k in MENU_ORDER]
