# Hackpot Telegram Resource Bot

Objective: Python Telegram bot (Dockerized) that receives resource links from authorized admins, classifies destination leaf categories with the Qwen decision-model API, collects the remaining entry info, and inserts the entry into J0nan/Hackpot READMEs on `main` using the sender's GitHub token.
Branch: `feat/hackpot-telegram-bot` (from `main`).
Delivery strategy: ask-on-risk.
Test runner: pytest + pytest-asyncio (`pip install -e .[dev]`; all external HTTP mocked via httpx.MockTransport; no live network or secrets in tests).

## Specs

Verbatim user strings are authoritative; numbered for reference.

- **S1** "recive and clasify resourses authorize users supply. Then the bot will upload to the corresponding repo folder the resourse."
- **S2** "This bot will have a list of authorize user setted via docker compose."
- **S3** "And thouse user will send links to the bot. Then the bot will detect if the link is from Github and if it is retrive the Readme file. If it is not from Github it will ask the user for a summary on what the bot is about."
- **S4** "After that the bot will retrive from a link of a github repo (it will be setted on the docker compose)." — target repo is `J0nan/Hackpot`: "This is the repo where everything will be uploaded https://github.com/J0nan/Hackpot there is a current squeleton and guidelines on how everything should be uploaded."
- **S5** "the bot will call a decision model on qwencloud to determine where the resourse should go." — VERIFIED against the live API (see L4). Contract: `POST https://{host}/compatible-mode/v1/systemone`, `Authorization: Bearer {key}`, body `{model, state, questions}`; response `answers.{qid}` with `choice`/`noul`/`score`, `confidence`, `probabilities`. Limits: ≤16 questions, 1–255 options, state ≤65536 tokens.
- **S6** "The Key, URL and model should be retrive from the docker compose file."
- **S7** "the ones with a higher confidence of a setted value on the docker compose, will be presented to the Telegram user, so it can decide in which one it should be uploaded or to override the decision and uploaded it to a specific folder." — ranking uses `probabilities` per option; `CONFIDENCE_THRESHOLD` and `MAX_CANDIDATES_SHOWN` from compose; plus "Other folder…" override button listing all configured leaf categories.
- **S8** "it should be uploaded to the repository using the account of the Telegram user that sent the resource. For this the bot should ask for a Github API key, the first time an authorize users starts a conversation."
- **S9** "The bot must only respond to authorize chats." — authorization = Telegram numeric user ID only; username stored for audit (S18).
- **S10** "the bot will create a sqlite file as a DB to save all the important data an survive updates, restarts, etc."
- **S11** "Make the program using python."
- **S12** "Make all the code secure."
- **S13** Upload follows the target repo guidelines (resolved from J0nan/Hackpot `CONTRIBUTING.md`): one bullet per resource inside the leaf category README at `NN_Domain/Sub_Category/README.md`, under `## Resources`, format:
  `- [Name](https://canonical-url) — What it does and why it matters. \`type:tool\` \`free\` \`linux\``
  alphabetical by display name; types `tool|course|docs|wordlist|lab|article|video`; cost `free|paid|freemium`; optional platform tags. No star counts or badges (CI adds them).
- **S14** "When the user determines where the tools should be placed, ask for the rest information need to added it." — after placement is decided, the bot collects/confirmes: display Name, one-line description (what + why), type tag, cost tag, optional platform tags. Pre-filled from GitHub repo metadata when available; admin confirms or edits each.
- **S15** "All repos and resources must be public, so if the bot has any trouble getting some information, ask the user for it, and remember them that all links must me public."
- **S16** "just push the commit to master" / "Commit the tools directly to the main brach, as only the admins of the repo will be using it." — commit to `main` via Contents API (GET sha → insert → PUT). Assumption A1: if the chosen leaf `README.md` does not exist, create it from the skeleton template (title + description + empty `## Resources`).
- **S17** "Use Telegram user ID allways, but also save the username for audit purposes."
- **S18** (A2) Categories sent to the decision model come from `CATEGORIES_JSON` in compose: map `{"NN_Domain/Sub_Category": "criteria description", ...}` seeded with the 34 leaf categories of J0nan/Hackpot.

## Configuration (docker compose env)

| Var | Purpose |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot API token (SecretStr) |
| `AUTHORIZED_USERS` | Comma-separated Telegram numeric user IDs |
| `TARGET_REPO` | `J0nan/Hackpot` (owner/repo) |
| `TARGET_BRANCH` | `main` |
| `CATEGORIES_JSON` | JSON map leaf-path → criteria description (S13/S18) |
| `QWEN_API_URL` | `https://ws-ej2s1sl5v6b81sgt.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/systemone` (per-compose; host is workspace-dedicated) |
| `QWEN_API_KEY` | sent as `Authorization: Bearer <key>` (verified) |
| `QWEN_MODEL` | `decision-model-preview` |
| `CONFIDENCE_THRESHOLD` | min option probability to show as candidate (default 0.15) |
| `MAX_CANDIDATES_SHOWN` | max option buttons (default 3) |
| `DB_PATH` | SQLite file on named volume (default `data/hackpot.sqlite3`) |
| `SECRETS_ENCRYPTION_KEY` | Fernet key (base64, 32-byte) for PATs at rest |
| `RATE_LIMIT_PER_MIN` | per-user message rate limit (default 10) |

## Architecture

```
hackpot/
  app/
    config.py        # pydantic-settings, env-only, fail-fast validation (DONE T1)
    main.py          # entrypoint (aiogram polling)          [T6]
    db/              # aiosqlite, WAL, schema init at startup [T2]
    security/        # allowlist, Fernet PAT store, sanitizers, rate limit [T3]
    services/
      github.py      # README fetch + bullet insert + Contents commit [T4]
      decision.py    # Qwen systemone client (verified contract) [T5]
    bot/             # handlers, flow FSM, keyboards          [T6]
  Dockerfile  docker-compose.yml  .env.example  pyproject.toml  tests/
```

Stack (Q3 resolved: best tool): **aiogram 3.31** (FSM, inline keyboards), **httpx**, **aiosqlite**, **cryptography** (Fernet), **pydantic-settings**. Pinned exact in pyproject.

## Flow

1. Gate: numeric-ID allowlist (`AUTHORIZED_USERS`); unauthorized → silent ignore + audit row (S9, S17).
2. `/start`: if no stored PAT → ask for GitHub token (BOT_TOKEN-scope message deleted after encrypted save; advice: fine-grained PAT, `contents:write` on Hackpot only, revocable) (S8).
3. Link in → detect GitHub repo URL (`github.com/owner/repo`, tolerant of `/tree/…`, `.git`, case) → fetch README + repo description via GitHub API, public only; on any fetch failure (private/404/rate-limit) ask the user for a summary and remind that all links must be public (S3, S15). Non-GitHub link → ask for a summary (S3).
4. Decision call: `state.content` = URL + README excerpt (≤ ~6k chars) / summary; questions: `folder` choice over `CATEGORIES_JSON`, `cost` choice, `needs_admin` noul (S5).
5. Candidates: options with probability ≥ `CONFIDENCE_THRESHOLD`, top `MAX_CANDIDATES_SHOWN` buttons (+ % display), plus **"Other folder…"** full-list override; if `needs_admin` P(yes) ≥ 0.5 show a "review carefully" note (S7).
6. After placement → entry interview: pre-filled Name / description / type / cost / platforms, confirm-or-edit; live preview of the bullet line (S14, S13).
7. Commit to `TARGET_REPO` on `main` with the **sender's** PAT: GET leaf README (content+sha) → insert alphabetically (duplicate URL → abort with message) → PUT Contents API; missing README → create from template (A1) (S13, S16).
8. Reply with commit URL + stored audit trail; SQLite holds everything and resumes pending flows across restarts (S10).

## Security

- Secrets env-only; `.gitignore` protects `POC-decision-model/token|workspace`, `.env`, `data/`; image `python:3.12-slim`, non-root UID 10001, read-only rootfs, single named volume for `data/`.
- PATs Fernet-encrypted at rest; never logged/echoed (mask `ghp_…abcd`); bot deletes the token message after capture.
- Path safety: commit path must be an exact key of `CATEGORIES_JSON` (no user-controlled path components); bullets escaped/sanitized (no raw newlines, length caps, `|` and backtick handling); URLs https-only, ≤2000 chars.
- No replies to unauthorized chats; per-user rate limiting; 30s timeouts, bounded retries (2) on all HTTP; strict error pages, no internal detail leaks.
- Duplicate-entry guard and branch-sha race handled (409 → refetch+retry once).

## Tasks

| ID | S# | Route | Status | Commit |
|---|---|---|---|---|
| T1 | S6, S11 | scaffold: pyproject, config, Dockerfile, compose, .env.example, .gitignore — INLINE (parent) | pending | — |
| T2 | S10 | `app/db/` schema + repository + resume — WRITER (parallel unit) | pending | — |
| T3 | S2, S8, S9, S12, S17 | `app/security/` authz, Fernet store, sanitizers, rate limiter — WRITER | pending | — |
| T4 | S3, S4, S13, S15, S16 | `app/services/github.py` URL detect, README fetch, bullet insert, commit — WRITER | pending | — |
| T5 | S5, S6, S7 | `app/services/decision.py` Qwen client + parser — WRITER | pending | — |
| T6 | S1–S9, S14 | `app/bot/` + `app/main.py`: handlers, FSM, keyboards, wiring — after T2–T5 seam (route decided then) | pending | — |
| T7 | S12 | hardening + docs + docker build smoke + full suite | pending | — |

Writer trigger evidence (post-L4): T2–T5 = four independent units of behavior, disjoint edit surfaces, each several files + tests (≈100+ lines) → delegated parallel writers in the same tree with declared surfaces; parent owns git + seam check.

## Log

- **L1** (user, original request, verbatim): "Plan the creation of a Telegram bot using Dockerfile and docker compose. The main purpose of the bot is to recive and clasify resourses authorize users supply. Then the bot will upload to the corresponding repo folder the resourse. This bot will have a list of authorize user setted via docker compose. And thouse user will send links to the bot. Then the bot will detect if the link is from Github and if it is retrive the Readme file. If it is not from Github it will ask the user for a summary on what the bot is about. After that the bot will retrive from a link of a github repo (it will be setted on the docker compose). With this information, the bot will call a decision model on qwencloud to determine where the resourse should go. [...] The Key, URL and model should be retrive from the docker compose file. With the results, the ones with a higher confidence of a setted value on the docker compose, will be presented to the Telegram user, so it can decide in which one it should be uploaded or to override the decision and uploaded it to a specific folder. After a category has being decided, it should be uploaded to the repository using the account of the Telegram user that sent the resource. For this the bot should ask for a Github API key, the first time an authorize users starts a conversation. The bot must only respond to authorize chats. And the bot will create a sqlite file as a DB to save all the important data an survive updates, restarts, etc. Before coding make a plan so I can review it and make the necesary changes. Make any questions of any implementation. Make the program using python. Make all the code secure. And delegate task in order no to consume all the context."
- **L2** Plan v1 written for review. No implementation authorized yet.
- **L3** (user answers, verbatim, 2026-10-25): "1: I have added a folder called POC, with a python that shows how to use the API, and two files containing the token and the workspace ID so you can try it and see how the API works and what it responds. 2: This is the repo where everything will be uploaded https://github.com/J0nan/Hackpot there is a current squeleton and guidelines on how everything should be uploaded. When the user determines where the tools should be placed, ask for the rest information need to added it. As the administrators will use the bot, just push the commit to master. 3: Use the best tool for the job, I do not have preferences on what to use. 4: Use Telegram user ID allways, but also save the username for audit purposes. 5: Commit the tools directly to the main brach, as only the admins of the repo will be using it. 6: All repos and resources must be public, so if the bot has any trouble getting some information, ask the user for it, and remember them that all links must me public. Remember to delegate any task you can and to ask any question you have." — implementation authorized.
- **L4** Evidence gathered: (a) `POC-decision-model/POC-systemone.py` documents the verified System One contract (Bearer auth, host `ws-ej2s1sl5v6b81sgt.ap-southeast-1.maas.aliyuncs.com`). (b) Live API call executed with the provided token — response: `answers.folder = {choice: "02_Web_Application/Vulnerability_Specific", confidence: 0.75, probabilities: {…}}`, noul returns P(yes) (0.02), score returns value+legend+probabilities; latency 560ms; `usage.input_tokens`. (c) J0nan/Hackpot tree mapped: 11 numbered domains, 34 leaf subcategories each with a README holding `## Resources`; CONTRIBUTING entry format captured in S13; `scripts/resource_meta.py` shows CI auto-appends stars — bot must NOT add them. (d) Local repo has remote `origin=https://github.com/J0nan/Hackpot_bot`, one commit on `main`, `.gitignore` added to keep `POC-decision-model/token`, `workspace`, `.env`, `data/` out of git.
- **L5** Open assumptions: A1 (missing leaf README → create from template), A2 (categories via CATEGORIES_JSON seeded from repo tree). Override button lists exactly the configured leaves — arbitrary paths are never accepted.
