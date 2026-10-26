# Hackpot Telegram Resource Bot

A Dockerized Python bot that turns a link sent in Telegram into a properly formatted
entry in the [J0nan/Hackpot](https://github.com/J0nan/Hackpot) index. Authorized admins
send a URL; the bot reads the public README (or asks for a summary), calls the Qwen
**decision model** to propose destination folders, collects the remaining entry fields,
shows a preview, and commits the bullet to `main` **under the sending admin's own GitHub
account**. Everything is persisted in SQLite on a named volume, so an in-progress
conversation survives a restart.

There is no web UI and no daemon to install beyond Docker: the bot long-polls Telegram,
and all configuration comes from one `.env` file.

---

## Quickstart

1. **Create the bot** — talk to [@BotFather](https://t.me/BotFather) → `/newbot` → copy the
   token (`123456789:AA...`).
2. **Generate the encryption key** (Fernet, 32-byte base64 — the only key that can decrypt
   stored GitHub tokens):

   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. **Collect numeric Telegram user IDs** — the bot only answers these IDs. Message
   [@userinfobot](https://t.me/userinfobot) (or any ID bot) and note the number, not the
   `@username`.
4. **Create `.env`** in the project root: copy the shipped `.env.example` template and
   replace every `REPLACEME` value (`.env` is git-ignored; `.env.example` is the tracked
   template with placeholders only — and note the `CATEGORIES_JSON` leaf descriptions
   are seeded guesses worth refining for your corpus).
5. **Start it:**

   ```bash
   docker compose up -d --build
   docker compose logs -f bot
   ```

6. **Verify** — `/start` in Telegram answers with the token request; the logs show polling
   starting and no traceback.

---

## Bot commands (BotFather registration)

The bot implements exactly these four commands (`app/bot/handlers.py`). Register them in
the BotFather chat with `/setcommands` and paste this block as-is:

```text
start - Add a resource: asks for your GitHub token once, then takes links
help - Show usage
cancel - Drop the current resource, nothing gets committed
forget - Delete my stored GitHub token
```

Optional, same flow — `/setname`, `/setdescription` and `/setabouttext` set the menu text;
a neutral description works well, e.g. "Curated Hackpot resource submissions — authorized admins only."

Notes:

- Descriptions after the ` - ` are free text but must stay short; Telegram shows them in the
  client's command menu (the `/…` hint list).
- The command menu is visible to **everyone** who opens the bot — that is cosmetic only.
  The bot silently ignores every update from an ID not in `AUTHORIZED_USERS`, so non-admins
  clicking `/start` get no response at all.
- Re-run `/setcommands` after any future command additions; the README table above should
  stay in sync with the code.

---

## Configuration (`.env`)

Every value is read from the environment by `app/config.py` and validated at startup —
a bad value stops the container before it opens any connection, and the error message
names the offending variable.

| Var | Required | Default | Semantics |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | yes | — | BotFather token. Treated as a secret, never logged. |
| `AUTHORIZED_USERS` | yes | — | Comma-separated **numeric** Telegram user IDs, e.g. `123456789,987654321`. At least one, all positive. Usernames are stored for audit only; authorization is by ID. |
| `TARGET_REPO` | no | `J0nan/Hackpot` | `owner/repo` that receives the commits. |
| `TARGET_BRANCH` | no | `main` | Branch the Contents API writes to. |
| `CATEGORIES_JSON` | yes | — | JSON map of leaf category path → decision-model criteria (see below). |
| `QWEN_API_URL` | yes | — | `https://…/compatible-mode/v1/systemone`. Must be `https://`. |
| `QWEN_API_KEY` | yes | — | Sent as `Authorization: Bearer <key>`. Never logged or echoed. |
| `QWEN_MODEL` | no | `decision-model-preview` | Model name in the request body. |
| `CONFIDENCE_THRESHOLD` | no | `0.15` | Minimum option probability (0–1) for a folder to be offered as a candidate. |
| `MAX_CANDIDATES_SHOWN` | no | `3` | Maximum candidate buttons (1–10). |
| `DB_PATH` | no | `data/hackpot.sqlite3` | SQLite file. **Inside the container the image already sets `/app/data/hackpot.sqlite3`** — leave it unset there, or keep any override under `/app/data/`, or the database lands outside the volume and disappears on rebuild. |
| `SECRETS_ENCRYPTION_KEY` | yes | — | Fernet key from step 2. Rotating it orphans every stored token (users must `/start` again). |
| `RATE_LIMIT_PER_MIN` | no | `10` | Messages per user per minute (1–1000); over budget gets one "slow down" reply. |
| `LOG_LEVEL` | no | `INFO` | Stdlib level — `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` (case-insensitive), drives stdout verbosity. See **Logging & debugging** below; credentials are redacted at every level. |
| `CATEGORY_SYNC_ENABLED` | no | `true` | Master switch for the daily automatic category refresh (see **Daily category auto-sync** below). |
| `CATEGORY_SYNC_TIME` | no | `00:00` | Local wall-clock `HH:MM` (24-hour) of the daily refresh; a sync also runs once at every startup. In docker the container clock is UTC unless `TZ` is set. |
| `CATEGORY_SYNC_KEEP_CURATED` | no | `false` | `true` protects hand-tuned criteria: the daily sync then fills only blank/placeholder leaves instead of overwriting with README intros. |
| `GITHUB_TOKEN` | no | — | Optional read-only token. Raises the GitHub rate limit for the daily sync and `scripts/sync_categories.py`. Never logged. |

### `CATEGORIES_JSON` shape

Keys must be exact leaf paths of the target repo (`NN_Domain/Sub_Category`), and each value
is the one-line criteria the model reads when deciding placement — write what belongs in
that folder, not just its name.

```json
{
  "01_Recon_and_OSINT/OSINT": "passive OSINT and reconnaissance resources",
  "02_Web_Application/Vulnerability_Specific": "tooling for one specific web vulnerability class"
}
```

The commit path is always `<key>/README.md`, so a key that is not configured can never be
committed to — this is the path-traversal gate.

Seeded leaf categories currently available in `J0nan/Hackpot` (11 domains, **31 leaves**,
verified against `main`; note that the ODD feature doc still carries a plan-time figure of
34 — trust the live tree and regenerate this list when in doubt):

```
01_Recon_and_OSINT            OSINT · Port_Scanning · Subdomain_Enumeration
02_Web_Application            Directory_Bruteforcing · Proxies_and_Scanners · Vulnerability_Specific
03_Network_and_Infrastructure  Active_Directory · Packet_Analysis · Wireless_and_Radio
04_Exploitation_and_PrivEsc    Exploitation_Frameworks · Linux_PrivEsc · Windows_PrivEsc
05_Reverse_Engineering         Disassemblers · Malware_Analysis
06_Cryptography_and_Cracking   Password_Cracking · Steganography
07_Hardware_IoT_and_ICS        Automotive_and_CAN_Bus · Hardware_Hacking · ICS_and_SCADA · IoT_and_Smart_Devices
08_Cloud_and_Containers        Cloud_Providers_AWS_Azure_GCP · Docker_and_Kubernetes
09_Wordlists_and_Payloads      Dictionaries · Reverse_Shells
10_Learning_and_Resources      Blogs_and_Podcasts · Cheat_Sheets · Practice_Labs
11_AI_and_Machine_Learning     AI_Assisted_Offensive_Tools · AI_Coding_Tools · Adversarial_ML_and_Model_Security · LLM_Security_and_Prompt_Injection
```

### Daily category auto-sync

The repo structure is the source of truth: the bot's background task syncs the categories **once at startup and then every day at `CATEGORY_SYNC_TIME`**
(local, default `00:00`) — it fetches the live leaf tree of `TARGET_REPO@TARGET_BRANCH`
plus each leaf's README intro, validates the merged map with the same contract as
`CATEGORIES_JSON`, and **hot-swaps `settings.categories`** — the next decision request
and the next category keyboard already use the fresh leaves, no restart needed. A sync
that fails (at startup or at the slot) is logged, keeps the current categories in force,
and simply retries at the next slot. When the process can
see a `.env` file (local runs) it is rewritten too, with a rolling `.env.bak`;
inside docker compose the container has no `.env`, so only the in-memory swap
happens. A failed or empty tree is refused and logged — the current
categories stay in force and the next slot retries.

If a keyboard was opened before midnight, its option buttons still carry the
pre-swap order; resolving them after the swap picks the category at that index
in the new list. Confirm destinations are always validated against the live
map, so nothing commits outside configured leaves.

`python scripts/sync_categories.py` (same logic, `--dry-run` available) remains
the manual on-demand refresh and the only writer that keeps the host `.env`
current while the bot runs in docker.

---

## Logging & debugging

The bot logs to **stdout** with the standard levels, driven by one environment
variable. Docker captures stdout, so `docker compose logs` is the only interface
you need — there is no log file and the read-only rootfs is never touched.

```bash
docker compose logs -f bot      # live stream, exactly what the container prints
```

Raise the level by setting `LOG_LEVEL` in `.env` and recreating the container:

```bash
# .env
LOG_LEVEL=DEBUG
docker compose up -d --force-recreate
```

`LOG_LEVEL` accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
(case-insensitive). The default is `INFO`; an invalid value stops the container at
startup with an error naming the allowed values.

### What each level emits

| Level | What you get |
|---|---|
| `DEBUG` | GitHub request summaries (`GET`/`PUT` + path + branch, content is never logged beyond a byte count) and bot state transitions (`state res=<id> OLD->NEW`). |
| `INFO` | The startup banner and "starting Telegram polling"; milestones — PAT captured, resource created, README fetched, `decision ok request_id=<id> folder=<chosen> candidates=<n>`, `github commit ok … url=<commit>`, and `milestone=commit_done res=<id>`. |
| `WARNING` | Decision retries (`decision attempt <n>/3 failed with HTTP <status> (<class>); retrying`), decision/fetch/commit failures (carrying the HTTP status and a `res=<id>` correlation token), duplicate commits, and ignored updates from unauthorized chats (id + username only). |
| `ERROR` | Unexpected exceptions with a full traceback — most often the polling loop dying (e.g. a Telegram **401** from a bad/revoked `TELEGRAM_BOT_TOKEN`), or a decision request exhausting its retries. |
| `CRITICAL` | A valid `LOG_LEVEL` ceiling, but nothing in the app emits it today — it is reserved for an operator who wants to silence everything below a fatal alert. |

`res=<id>` (the resource id) and `request_id` tie a burst of lines back to one
submission; filter the stream with `docker compose logs bot | grep "res=7"`.

### Three worked symptoms

1. **`Restarting` loop after a bad token** — the Telegram **401** surfaces as an
   `ERROR` line with a traceback (`[app.main] unexpected error during polling`).
   The traceback names the failure but **never prints the token** (it is redacted
   at the handler). Fix `TELEGRAM_BOT_TOKEN` and recreate.
2. **Decision retry storm** — raise `LOG_LEVEL` and you see the sequence, e.g.:
   ```
   WARNING … [app.services.decision] decision attempt 1/3 failed with HTTP 500 (5xx); retrying
   WARNING … [app.services.decision] decision attempt 2/3 failed with HTTP 503 (5xx); retrying
   WARNING … [app.services.decision] decision attempt 3/3 rejected with HTTP 503 (5xx)
   ```
   That points at the decision API, not your inputs.
3. **A failed classification** — the flow logs the audited reason with its
   correlation token, e.g. `WARNING … [app.bot.flow] decision_failed res=7: …`, and
   the successful path would instead show
   `INFO … decision ok request_id=req-… folder=… candidates=2`. The `request_id`
   matches the row written to the `decisions` audit table.

### Credentials never reach the log stream

Every record — **including lines emitted by third-party loggers such as
aiogram** — passes through a redaction filter attached to the one stdout handler.
The configured bot token and Qwen key, and any shaped secret (`ghp_`/`gho_`/
`ghu_`/`ghs_`/`ghr_`, `github_pat_`, `sk-…`, or an `Authorization: …` header) in
the message **or a formatted exception traceback**, are replaced by `***` before
the line is written. This is enforced below your code, so a debug line — or a
crash — can never leak a credential, at any log level.

---

## Flow

```
authorized admin ──/start──▶ no PAT stored? ──▶ asks for one GitHub token
                                (encrypted at rest, your message deleted)
        │
        ▼
 send ONE https link
        ├── github.com/owner/repo ──▶ fetch repo description + README (public only)
        │                                     │ fails (private/404/rate-limit)
        └── any other resource ───────────────┴─▶ asks for a short summary
        │
        ▼
 "🤔 Analyzing… send /cancel anytime"     ◀── sent BEFORE the decision call (worst case ~93 s)
        │
        ▼
 decision model over CATEGORIES_JSON ──▶ candidate buttons (probability ≥ threshold,
        top MAX_CANDIDATES_SHOWN) + "📂 Other folder…" (every configured leaf, paged)
        │
        ▼
 entry interview: name → description → type → cost → platforms  (GitHub metadata prefilled)
        │
        ▼
 preview of the exact bullet ──✅ Commit / ❌ Cancel──▶ GET leaf README sha → insert
                                                        alphabetically → PUT Contents API
        │
        ▼
 commit URL + audit rows in SQLite (resumes where it stopped after a restart)
```

---

## Using the bot as an admin

- **First `/start`** asks for your GitHub token, once. Send the bare token as a single
  message; the bot encrypts it and deletes your message.
- **Send a link** — exactly one `https` URL per message. GitHub repos are read
  automatically; anything else gets a summary question.
- **Pick a folder** — the candidate buttons show the model's confidence; `📂 Other folder…`
  lists every configured leaf, paged, so you can always override the decision. Arbitrary
  paths are never accepted.
- **Answer the interview** — display name, one-line description (what it does and why it
  matters), `type`, `cost`, optional platform tags. `none` skips platforms.
- **Confirm** — the preview shows the exact bullet; ✅ commits to `TARGET_BRANCH`, ❌ or
  `/cancel` drops the resource without touching the repo.
- **`/forget`** deletes your stored token (rotate a revoked PAT this way), then `/start`
  to save the new one. **`/help`** prints the command list; **`/cancel`** aborts the
  current resource at any step.

Entry rules are those of the target repo (its `CONTRIBUTING.md`): one bullet per resource
inside the leaf's `## Resources`, alphabetical by display name.

```markdown
- [Name](https://canonical-url) — What it does and why it matters. `type:tool` `free` `linux`
```

Types are `tool|course|docs|wordlist|lab|article|video`, cost `free|paid|freemium`, plus
optional platform tags. The bot inserts alphabetically, aborts a duplicate URL, and never
adds star counts or badges (the repo's CI appends those). A missing leaf README is created
from the standard skeleton.

---

## GitHub token policy

- Use a **fine-grained personal access token** scoped to the **single target repository**,
  with **Contents: Read and write** only. No metadata-only or classic tokens: they carry far
  more than this bot needs.
- **Set an expiry** (recommended) and rotate it periodically; rotation is `/forget` then
  `/start` with the new token. Nothing else has to change.
- Commits are made **with the sender's token**, so they appear in the repository under each
  admin's own account — the bot never commits as a service account, and no shared bot
  credential can be abused to write.
- Tokens are Fernet-encrypted at rest, never echoed back, and only masked (`ghp_…abcd`) in
  the audit trail.

---

## Security model

| Area | How it is handled |
|---|---|
| Secrets | Environment only — never in the image, never in git, never in a reply or log line. |
| GitHub tokens | Fernet-encrypted in SQLite; the capture message is deleted; masked in audit rows. |
| Authorization | Numeric Telegram ID allowlist (`AUTHORIZED_USERS`). Unauthorized chats get **no reply at all** — only an audit row. |
| Path safety | The commit path is an exact `CATEGORIES_JSON` key + `/README.md`. Callback buttons carry a **strict canonical digit index** (`^\d+$`, ASCII only) into that list, so `c: 1`, `c:+1`, `c:01` or `c:١` are rejected exactly like `c:abc`. A tampered/stale database row whose folder is not configured is refused at confirm time (`commit_rejected` audit row, nothing committed, the resource stays reviewable). |
| Input hygiene | URLs: https-only, no credentials, ≤ 2000 chars. Text: one-line sanitized (newlines, control/zero-width/bidi characters, HTML comment spans removed, length-capped). Names/descriptions containing `[`, `]` or a backtick are refused — the bullet-injection guard. |
| Backpressure | `RATE_LIMIT_PER_MIN` per user; every HTTP call uses a 30 s timeout with at most 2 retries. The decision call announces itself before it starts. |
| Container | `python:3.12-slim`, runs as non-root **UID 10001**, `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges`, writable only at the `/app/data` named volume (plus a tmpfs `/tmp`). |
| Errors | Users see short static wording; HTTP statuses, request IDs and internal details go to the audit table instead. |

---

## Data and recovery

SQLite in WAL mode lives on the `hackpot-data` volume: `users`, `github_tokens`
(ciphertext), `resources` (the state machine), `decisions`, and `audit_log`.

- **Restart-safe:** mid-conversation state is in `resources.state`, so `docker compose
  restart` resumes an interview or a placement prompt exactly where it stopped.
- **Audit trail:** every gate, decision, rejection and commit writes a row — sufficient to
  answer "who added this, when, and why did the model suggest that folder".
- **Retention (known gap):** `audit_log` and `decisions` are append-only and **unbounded**.
  For a handful of admins this grows slowly, but a retention prune is a deliberate future
  ops item (L7-8) — not implemented. Until then, back up the volume periodically;
  `data/` is git-ignored, so a rebuild never touches it.
- **Backup/restore:** `docker compose down` then copy the volume, or
  `docker run --rm -v hackpot_bot_hackpot-data:/d -v "$PWD:/b" alpine cp -a /d/. /b/backup/`.

---

## Running the tests

No network, no live bot: every external HTTP call is mocked and the database is a temp
file.

```bash
pip install -e .[dev]
python -m pytest tests/ -q
```

`pyproject.toml` adds `-p no:libtmux`: a user-site `libtmux` installs a `pytest11` plugin
that crashes pytest 9.1 collection machine-wide. The flag is harmless where libtmux is not
installed (CI, Docker).

---

## Manual live smoke (needs a real bot token)

The automated suite cannot prove Telegram polling or a real commit — run this once per
deployment (L11-d):

- [ ] `docker compose up -d --build`, then `docker compose logs --tail 25 bot` shows polling
      with no traceback.
- [ ] `/start` from an authorized ID → the bot asks for a GitHub token.
- [ ] Send a fine-grained PAT → "Token stored (encrypted)" and **your message disappears**.
- [ ] Send a public test link (e.g. a small repo you own) → `🤔 Analyzing…` arrives
      immediately, then candidate buttons with percentages.
- [ ] Pick a folder (and once via `📂 Other folder…`), answer the interview, confirm the
      preview.
- [ ] ✅ Commit → the bot replies with a commit URL; open it and check the bullet landed in
      the right leaf, alphabetically, under **your** GitHub account.
- [ ] Start a second resource, and mid-interview run `docker compose restart bot` → resend a
      field: the bot continues the same interview instead of restarting it.
- [ ] `/cancel` aborts cleanly; `/forget` deletes the token and `/start` asks again.
- [ ] Send a link from an **unauthorized** account → silence (check the audit row appeared).

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Restarting` loop; logs show `Unauthorized` / Telegram **401** | Wrong or revoked `TELEGRAM_BOT_TOKEN`. The traceback is safe — it never prints the token. Re-copy it from BotFather (the whole string, including the colon). |
| Commit fails with **403**, `Resource not accessible by personal access token` | The PAT lacks **Contents: Read and write**, is classic/expired, or is scoped to the wrong repository. `/forget`, then `/start` with a correctly scoped fine-grained token. |
| "already listed … nothing was committed" | The URL is already in that leaf README. Pick a different folder, or edit the existing entry by hand. |
| "couldn't reach that repository… all links must be public" | The repo is private, renamed, or rate-limited. The bot reads as **your** PAT, so an org repo needs the PAT to include it. Reminder: every indexed resource must be public. |
| Container exits at startup and `docker compose ps` shows `Restarting` | A required variable is missing/invalid (empty `CATEGORIES_JSON`, a key that is not `NN_Domain/Sub_Category`, a non-`https` `QWEN_API_URL`, an invalid Fernet key, a bad `AUTHORIZED_USERS`). Settings validate before any I/O, so `docker compose logs bot` names the offending variable — fix `.env` and `docker compose up -d`. |
| `attempt to write a readonly database` | `DB_PATH` points outside `/app/data` (the rootfs is read-only). Unset it, or keep it under `/app/data/`. |
| The bot ignores messages | That Telegram ID is not in `AUTHORIZED_USERS` — IDs, not usernames. Recreate the container after editing `.env`. |
| Nothing happens after `🤔 Analyzing…` for a minute | The decision API is retrying (worst case ~93 s). `/cancel` aborts the resource; check the `decision_failed` audit row and `QWEN_API_URL`/`QWEN_API_KEY`. |
