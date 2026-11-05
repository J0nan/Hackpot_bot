"""User-visible bot wording and shared limits."""

from __future__ import annotations

from app.services.github import ENTRY_TYPES

README_EXCERPT_CHARS = 6000


SUMMARY_MAX_CHARS = 6000


_STATS_DISPLAY_LIMIT = 10


_NAME_MAX = 120


_DESC_MAX = 500


_MAX_CONTEXT_CHARS = 2 * SUMMARY_MAX_CHARS


NEEDS_ADMIN_THRESHOLD = 0.5


SLOW_DOWN = "You are sending too fast — please slow down and try again in a minute."


ASK_PAT_START = (
    "👋 Welcome, Hackpoter! First, send me your GitHub Personal Access Token "
    "as one bare message.\n"
    "Here you can create one: https://github.com/settings/personal-access-tokens/new?name=Hackpot%20Bot&target_name=HackPot-HQ\n"
    "Set the following:\n"
    "    - Expiration to 'No expiration'.\n"
    "    - Select 'Only selected repositories' and choose the 'Hackpot' repo on the "
    "Repository access.\n"
    "    - Under 'Repository permissions', select 'Add permissions' then add "
    "'Contents' and set it to 'Read and write'.\n\n"
    "Generate the token, copy it, and send it to me as one bare message.\n"
    "I will store it encrypted. It is used to commit the resource under your own GitHub account.\n"
    "Remember: all links must be public."
)


GREETING_READY = (
    "👋 Welcome back! Send the https link of the resource you want indexed. GitHub "
    "repo links are read automatically; for anything else I will ask you for a "
    "short summary.\nRemember: all links must be public."
)


PAT_SAVED = (
    "✅ Token stored (encrypted). Send the https link of the resource you want "
    "indexed. \nRemember: all links must be public."
)


PAT_STILL_NEEDED = (
    "I still need your GitHub token, send the bare token as one message "
    "(stored encrypted, never echoed back)."
)


NEED_TOKEN_FOR_LINK = (
    "Before I can index that link, send me your GitHub Personal Access Token.\n"
    "Here you can create one: https://github.com/settings/personal-access-tokens/new?name=Hackpot%20Bot&target_name=HackPot-HQ\n"
    "Set the following:\n"
    "    - Expiration to 'No expiration'.\n"
    "    - Select 'Only selected repositories' and choose the 'Hackpot' repo on the "
    "Repository access.\n"
    "    - Under 'Repository permissions', select 'Add permissions' then add "
    "'Contents' and set it to 'Read and write'.\n\n"
    "Generate the token, copy it, and send it to me as one bare message.\n"
    "I will store it encrypted. It is used to commit the resource under your own GitHub account.\n"
    "Remember: all links must be public."
)


USAGE_HINT = (
    "Send exactly one https link (for example https://github.com/owner/repo). For a "
    "non-GitHub resource, send just its link and I will ask for a summary. "
    "Remember: all links must be public."
)


ASK_SUMMARY = (
    "Send me a short summary of what that resource is about — remember: all "
    "links must be public."
)


ALREADY_COMMITTED = "⚠️ That link is already on file in 📁 {folder} — nothing new was created."


ALREADY_IN_PROGRESS = (
    "⚠️ That link is already being processed (resource #{resource_id}{folder_part}). "
    "It has not been committed yet — try again once it finishes."
)


ALREADY_COMMITTED_OUTSIDE = (
    "⚠️ That link is already listed in 📁 {folder} of the Hackpot repo "
    "(added outside this bot) — nothing new was created."
)


ANALYZING = "🤔 Analyzing… send /cancel anytime"


DECISION_UNRELIABLE_USER = (
    "🤖 The decision model did not return a reliable result — nothing was "
    "suggested. Send a few words about this resource and I'll classify it "
    "again with that extra context, or press 🛠️ Manual classify to pick a "
    "folder yourself."
)


MANUAL_PLACEMENT_NOTE = (
    "🛠️ Manual classification it is — pick a folder by its number below. "
    "Text messages no longer count as classification context for this resource."
)


PLACEMENT_HINT = (
    "Pick a destination folder — press its number above (📂 Other folder… "
    "lists every category)."
)


UNKNOWN_FOLDER = "That folder is not in the configured category list."


ASK_NAME = "What display name should the entry use? (one line, no [ ] or backticks)"


ASK_DESCRIPTION = (
    "Now the description — one line: what it does and why it matters "
    "(no [ ] or backticks)."
)


ASK_TYPE = "Pick the type tag:"


ASK_PLATFORMS = (
    "Optional platform/tech tags, space-separated (e.g. linux docker), "
    'or send "none".'
)


ASK_CONTEXT = (
    "Give me a one-line description of what this resource is — remember: all "
    "links must be public."
)


INVALID_FIELD = "{label} can't contain [ ] or backticks — please re-send without them."


INVALID_TYPE = f"Pick one of: {', '.join(ENTRY_TYPES)}."


ENTRY_BUILD_FAILED = (
    "Some collected answers can't form a valid entry line — let's re-check them."
)


PLACED = "Placing in 📁 {folder}."


NEEDS_ADMIN_NOTE = (
    "⚠️ The model flags this as sensitive — please double-check the placement "
    "before committing."
)


PREVIEW = "Here is the entry bullet — confirm to commit:"


COMMITTED_REPLY = "✅ {status} → {url}"


COMMIT_REJECTED = (
    "⛔ That destination is not one of the configured categories — nothing was "
    "committed. Use /cancel, then send the link again."
)


CANCELLED_MSG = "🚫 Cancelled — nothing was uploaded. Send a new link any time."


NOTHING_PENDING = "There is nothing pending to cancel. /start to begin."


STATS_EMPTY = (
    "🏆 No links have been committed yet — the leaderboard is waiting for its first 🥇."
)


STATS_TAGS_EMPTY = "🏷️ No tags on file yet — tags ride the committed entries."


STATS_NO_COMMITS = "You have not committed any links yet."


CONFIRMING_HINT = (
    "Use the buttons above — ✅ Commit, ❌ Cancel, or ✏️ Description / 🏷️ Tags "
    "to edit one field before committing — or /cancel to abort."
)


EDIT_DESC_ASK = (
    "✏️ Copy the current description below, modify it (one line, no [ ] or "
    "backticks, at most 500 characters), then send the new description back. "
    "Nothing is committed until you press ✅ — the buttons above stay usable "
    "meanwhile."
)


EDIT_TAGS_ASK = (
    "🏷️ Copy the tags below, edit them on one line (the first tag must stay a "
    "`type:` tag, the rest are plain platform tags), then send the new tags "
    "back. Nothing is committed until you press ✅ — the buttons above stay "
    "usable meanwhile."
)


EDIT_DESC_ONE_LINE = "The description must be one line — send it again without line breaks."


EDIT_DESC_EMPTY = "The description is empty — send the new description on one line."


EDIT_DESC_TOO_LONG = (
    f"The description exceeds the {_DESC_MAX} character limit — shorten it and send it again."
)


EDIT_NO_TYPE_TAG = (
    "Missing type tag: the first tag must be one of "
    + ", ".join(f"`type:{tag}`" for tag in ENTRY_TYPES)
    + " — fix it and send the tags again."
)


EDIT_TYPE_VALUE = (
    "The type tag must be one of "
    + ", ".join(ENTRY_TYPES)
    + " — fix it and send the tags again."
)


EDIT_TAGS_COLON = (
    "Platform tags must be plain words without ':' — only the first tag may "
    "be a `type:` tag — fix it and send the tags again."
)


EDIT_UNAVAILABLE = "This entry can't be prepared for editing right now — use ✅ to commit or ❌ to cancel."


EDIT_RETRY_DETAIL_MAX = 200


FORGOTTEN = "🧹 Your stored GitHub token was deleted. /start to save a new one."


DECRYPT_FAILED = (
    "Your stored GitHub token could not be decrypted. Use /forget, then /start "
    "to save a new one."
)


UNKNOWN_CALLBACK = "That button is no longer available — /start or send the link again."


COMMIT_PUBLIC_REMINDER = " Remember: all links must be public."


COMMIT_IN_PROGRESS = (
    "⏳ That commit is already in flight — one moment. This press was ignored: "
    "nothing new was started and nothing was duplicated."
)


FLOW_INTERRUPTED = (
    "⏸️ The step I am waiting on is driven by buttons, so I did not treat "
    "that message as an answer. Press ▶️ Continue to re-send the current "
    "step's message (its card may also invite a text reply), or ❌ Cancel "
    "to drop this resource (or use /cancel anytime)."
)

