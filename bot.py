#!/usr/bin/env python3
"""
ETH gem scanner -> Telegram alerts.

Scans Ethereum DEX pools on GeckoTerminal, keeps coins that match the
activity filters, then runs safety checks (honeypot.is, GoPlus) and a
source-code backdoor check (Sourcify) before sending a Telegram alert.

All settings come from environment variables (see README.md).
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

# --------------------------------------------------------------------------
# Settings (override with environment variables / GitHub "Variables")
# --------------------------------------------------------------------------


def env_num(name, default):
    v = os.environ.get(name, "").strip()
    try:
        return float(v) if v else default
    except ValueError:
        return default


def env_bool(name, default):
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "y", "on")


MAX_FDV = env_num("MAX_FDV", 200_000)            # max market cap / FDV in USD
MIN_FDV = env_num("MIN_FDV", 5_000)              # ignore dust
MIN_AGE_H = env_num("MIN_AGE_HOURS", 3)          # min hours since pool launch
MIN_LIQ = env_num("MIN_LIQUIDITY", 4_000)        # min pool liquidity in USD
MIN_BUYERS_1H = env_num("MIN_BUYERS_1H", 5)      # min unique buyers last hour
MIN_VOL_1H = env_num("MIN_VOLUME_1H", 500)       # min USD volume last hour
MIN_PRICE_1H = env_num("MIN_PRICE_CHANGE_1H", 0)  # % change last hour must be above this
MAX_TAX = env_num("MAX_TAX_PERCENT", 5)          # max buy/sell tax %
MAX_TOP_WALLET = env_num("MAX_TOP_WALLET_PERCENT", 10)  # largest non-pool wallet %
MIN_LP_SAFE = env_num("MIN_LP_LOCKED_PERCENT", 90)      # % of LP burned/locked
REQUIRE_RENOUNCED = env_bool("REQUIRE_RENOUNCED", True)
REQUIRE_SOURCE = env_bool("REQUIRE_VERIFIED_SOURCE", True)
REQUIRE_SOCIALS = env_bool("REQUIRE_SOCIALS", False)  # False = socials only boost ranking
MAX_ALERTS = int(env_num("MAX_ALERTS_PER_RUN", 5))
REALERT_HOURS = env_num("REALERT_HOURS", 12)
SCAN_PAGES_NEW = int(env_num("SCAN_PAGES_NEW", 12))
DRY_RUN = env_bool("DRY_RUN", False)

TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TG_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

STATE_FILE = os.environ.get("STATE_FILE", "seen.json")

GT = "https://api.geckoterminal.com/api/v2/networks/eth/"
UA = {"User-Agent": "eth-gem-bot/1.0", "Accept": "application/json"}
SKIP_NAMES = re.compile(r"^(ETH|WETH|USDC|USDT|WBTC|DAI|STETH|WSTETH)\s*/", re.I)
ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dead"

session = requests.Session()
session.headers.update(UA)


def log(*a):
    print(datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

_last_gt = [0.0]


def gt_get(path):
    """GeckoTerminal GET with polite rate limiting (~25 req/min) and retries."""
    url = path if path.startswith("http") else GT + path
    for attempt in range(5):
        wait = 2.5 - (time.time() - _last_gt[0])
        if wait > 0:
            time.sleep(wait)
        _last_gt[0] = time.time()
        try:
            r = session.get(url, timeout=20)
        except requests.RequestException as e:
            log("GT error", e)
            time.sleep(5)
            continue
        if r.status_code == 200:
            return r.json()
        if r.status_code in (400, 404):
            return None
        if r.status_code == 429:
            time.sleep(15 + attempt * 10)
            continue
        time.sleep(5)
    return None


def get_json(url, timeout=25):
    for attempt in range(3):
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (400, 404):
                return None
        except (requests.RequestException, ValueError):
            pass
        time.sleep(3 + attempt * 3)
    return None


def f(x, default=0.0):
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------
# 1) Scan pools
# --------------------------------------------------------------------------


def pool_row(d):
    a = d["attributes"]
    pc = a.get("price_change_percentage") or {}
    tx = a.get("transactions") or {}
    vol = a.get("volume_usd") or {}
    base = (d.get("relationships", {}).get("base_token", {}).get("data") or {}).get("id", "")
    h1 = tx.get("h1") or {}
    h6 = tx.get("h6") or {}
    m15 = tx.get("m15") or {}
    fdv = f(a.get("fdv_usd"))
    mc = f(a.get("market_cap_usd"))
    return {
        "name": a.get("name", ""),
        "pool": a.get("address", ""),
        "dex": (d.get("relationships", {}).get("dex", {}).get("data") or {}).get("id", ""),
        "token": base.replace("eth_", "").lower(),
        "created": a.get("pool_created_at"),
        "fdv": fdv,
        "cap": mc if mc > 0 else fdv,
        "liq": f(a.get("reserve_in_usd")),
        "m15": f(pc.get("m15")),
        "h1": f(pc.get("h1")),
        "h6": f(pc.get("h6")),
        "h24": f(pc.get("h24")),
        "b15": m15.get("buys", 0) or 0,
        "s15": m15.get("sells", 0) or 0,
        "b1": h1.get("buys", 0) or 0,
        "s1": h1.get("sells", 0) or 0,
        "buyers1": h1.get("buyers", 0) or 0,
        "sellers1": h1.get("sellers", 0) or 0,
        "buyers6": h6.get("buyers", 0) or 0,
        "sellers6": h6.get("sellers", 0) or 0,
        "vol1": f(vol.get("h1")),
        "vol24": f(vol.get("h24")),
    }


def age_hours(created):
    try:
        t = datetime.fromisoformat(created.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - t).total_seconds() / 3600
    except Exception:
        return 0.0


def scan_pools():
    paths = []
    for dur in ("1h", "6h", "24h"):
        for p in (1, 2, 3):
            paths.append(f"trending_pools?duration={dur}&page={p}")
    for p in range(1, 6):
        paths.append(f"pools?sort=h24_tx_count_desc&page={p}")
    for p in range(1, SCAN_PAGES_NEW + 1):
        paths.append(f"new_pools?page={p}")
    pools = {}
    for path in paths:
        j = gt_get(path)
        if not j:
            continue
        for d in j.get("data") or []:
            try:
                row = pool_row(d)
            except Exception:
                continue
            pools[row["pool"]] = row
    log(f"scanned {len(pools)} pools from {len(paths)} pages")
    return list(pools.values())


def activity_ok(r):
    if SKIP_NAMES.match(r["name"]):
        return False
    if not (MIN_FDV <= r["cap"] <= MAX_FDV):
        return False
    if r["liq"] < MIN_LIQ:
        return False
    if age_hours(r["created"]) < MIN_AGE_H:
        return False
    if r["buyers1"] < MIN_BUYERS_1H or r["buyers1"] <= r["sellers1"]:
        return False
    if r["b1"] <= r["s1"]:
        return False
    if r["h1"] <= MIN_PRICE_1H:
        return False
    if r["vol1"] < MIN_VOL_1H:
        return False
    return True


# --------------------------------------------------------------------------
# 2) Safety checks
# --------------------------------------------------------------------------


def check_honeypot(token):
    j = get_json(f"https://api.honeypot.is/v2/IsHoneypot?address={token}&chainID=1")
    if not j:
        return {"ok": False, "why": "honeypot.is unavailable"}
    if j.get("error") or j.get("simulationError"):
        return {"ok": False, "why": f"sell simulation failed ({j.get('error') or j.get('simulationError')})"}
    hp = (j.get("honeypotResult") or {}).get("isHoneypot")
    sim = j.get("simulationResult") or {}
    buy, sell = f(sim.get("buyTax")), f(sim.get("sellTax"))
    hold = j.get("holderAnalysis") or {}
    failed = int(f(hold.get("failed")))
    if hp:
        return {"ok": False, "why": "honeypot (can't sell)"}
    if buy > MAX_TAX or sell > MAX_TAX:
        return {"ok": False, "why": f"tax buy {buy:.0f}% / sell {sell:.0f}%"}
    if failed > 0:
        return {"ok": False, "why": f"{failed} holder sells failed in simulation"}
    return {"ok": True, "buy": buy, "sell": sell, "holders_sim": int(f(hold.get("successful")))}


def check_goplus(token, pool_addr):
    j = get_json(f"https://api.gopluslabs.io/api/v1/token_security/1?contract_addresses={token}")
    r = ((j or {}).get("result") or {}).get(token) or {}
    if not r:
        return {"ok": False, "why": "GoPlus no data"}
    bad = []
    owner = (r.get("owner_address") or "").lower()
    renounced = owner in ("", ZERO, DEAD)
    if r.get("is_honeypot") == "1":
        bad.append("GoPlus honeypot")
    if r.get("is_open_source") != "1":
        bad.append("closed source")
    if r.get("is_proxy") == "1":
        bad.append("upgradeable proxy")
    if r.get("hidden_owner") == "1":
        bad.append("hidden owner")
    if r.get("can_take_back_ownership") == "1":
        bad.append("can reclaim ownership")
    if r.get("selfdestruct") == "1":
        bad.append("self-destruct")
    if r.get("cannot_sell_all") == "1":
        bad.append("cannot sell all")
    if REQUIRE_RENOUNCED and not renounced:
        bad.append("owner not renounced")
    if not renounced:
        for k, label in (("is_mintable", "mintable"), ("is_blacklisted", "blacklist"),
                         ("transfer_pausable", "pausable"), ("owner_change_balance", "owner can change balances"),
                         ("slippage_modifiable", "tax changeable")):
            if r.get(k) == "1":
                bad.append(label)

    # Liquidity lock
    dexes = r.get("dex") or []
    main = next((d for d in dexes if (d.get("pair") or "").lower() == pool_addr.lower()), dexes[0] if dexes else {})
    lp_type = main.get("liquidity_type", "")
    fee = f(main.get("pool_fee"))
    if lp_type == "UniV4" and fee > 0.05:
        bad.append(f"V4 pool fee {fee * 100:.0f}%")
    lp = r.get("lp_holders") or []
    lp_safe = 0.0
    for h in lp:
        a = (h.get("address") or "").lower()
        if str(h.get("is_locked")) == "1" or a in (ZERO, DEAD):
            lp_safe += f(h.get("percent"))
    lp_safe *= 100
    if not lp:
        bad.append("LP lock unknown")
    elif lp_safe < MIN_LP_SAFE:
        bad.append(f"only {lp_safe:.0f}% LP locked/burned")

    # Holder concentration (exclude pools, burn, lock contracts)
    top = 0.0
    for h in r.get("holders") or []:
        a = (h.get("address") or "").lower()
        if a in (ZERO, DEAD) or h.get("tag") or str(h.get("is_locked")) == "1":
            continue
        if a == pool_addr.lower() or a == "0x000000000004444c5dc75cb358380d2e3de08a90":
            continue
        top = max(top, f(h.get("percent")) * 100)
    if top > MAX_TOP_WALLET:
        bad.append(f"top wallet {top:.1f}%")

    return {
        "ok": not bad,
        "why": ", ".join(bad),
        "renounced": renounced,
        "lp_safe": lp_safe,
        "lp_type": lp_type,
        "holders": int(f(r.get("holder_count"))),
        "top_wallet": top,
        "creator": r.get("creator_address", ""),
        "lock_tag": next((h.get("tag") for h in lp if h.get("tag")), ""),
    }


# Patterns that indicate tricks like the Grokbot backdoors.
LIB_PATH = re.compile(r"(@openzeppelin|@uniswap|node_modules|lib/|solmate|solady)", re.I)


def strip_comments(src):
    src = re.sub(r"/\*[\s\S]*?\*/", "", src)
    return re.sub(r"//[^\n]*", "", src)


def code_flags(sources):
    """sources: dict path -> content. Returns list of red-flag strings."""
    flags = []
    own = {p: strip_comments(c) for p, c in sources.items() if not LIB_PATH.search(p)}
    libs = {p: c for p, c in sources.items() if LIB_PATH.search(p)}
    allsrc = "\n".join(own.values())

    if re.search(r"\btx\.origin\b", allsrc):
        flags.append("uses tx.origin")

    # balanceOf override that does more than return the stored balance
    for m in re.finditer(r"function\s+balanceOf\s*\([^)]*\)[^{]*\{([\s\S]*?)\n\s*\}", allsrc):
        body = re.sub(r"\s+", " ", m.group(1)).strip()
        if not re.fullmatch(r"return\s+(_balances\[\w+\]|super\.balanceOf\(\w+\)|_rOwned\[\w+\][^;]*|tokenFromReflection\([^;]*\));?", body):
            flags.append("custom balanceOf (can fake pool balance)")
            break

    # transferFrom that doesn't spend allowance by the real amount
    for m in re.finditer(r"function\s+transferFrom\s*\([^)]*\)[^{]*\{([\s\S]*?)\n\s*\}", allsrc):
        body = m.group(1)
        spends = re.search(r"_spendAllowance\s*\(", body) or re.search(
            r"_allowances\[[^\]]+\]\[[^\]]+\]\s*\.sub\(\s*(amount|value|_value|wad)\b", body) or re.search(
            r"_allowances\[[^\]]+\]\[[^\]]+\]\s*-\s*(amount|value|_value|wad)\b", body) or re.search(
            r"allowance\s*\([^)]*\)\s*-\s*(amount|value)\b", body)
        if not spends:
            flags.append("transferFrom skips/alters allowance check")
            break
        if re.search(r"\b_\w+\s*=\s*(amount|value)\s*;", body):
            flags.append("transferFrom stores amount in a variable (allowance bypass trick)")
            break

    # helper comparing caller to a stored wallet, used outside onlyOwner
    if re.search(r"_msgSender\(\)\s*==\s*_?\w+\s*\)\s*return\s+true", allsrc) or re.search(
            r"msg\.sender\s*==\s*(devWallet|marketingWallet|taxWallet|_\w*[Ww]allet)\b", allsrc):
        flags.append("special rules for a dev/marketing wallet")

    if re.search(r"\bassembly\s*\{", allsrc):
        flags.append("inline assembly")
    if re.search(r"\bdelegatecall\b", allsrc):
        flags.append("delegatecall")
    if re.search(r"\.sync\s*\(\s*\)", allsrc):
        flags.append("forces pool sync")
    if re.search(r"_balances\[[^\]]+\]\s*=\s*(?!_balances)[^;]+;", allsrc) and re.search(
            r"onlyOwner|_msgSender\(\)\s*==", allsrc):
        # direct balance writes are normal inside _transfer; flag only if inside an admin-gated function
        for fm in re.finditer(r"function\s+(\w+)\s*\([^)]*\)([^{]*)\{([\s\S]*?)\n\s*\}", allsrc):
            name, mods, body = fm.group(1), fm.group(2), fm.group(3)
            if name.startswith("_transfer") or name in ("_update", "_mint", "_burn", "constructor"):
                continue
            if re.search(r"_balances\[[^\]]+\]\s*[-+]?=", body) and ("onlyOwner" in mods or "_msgSender" in body):
                flags.append(f"admin can edit balances ({name})")
                break

    # Modified OpenZeppelin library files (very rare legitimately)
    for p, c in libs.items():
        if "ERC20.sol" in p and re.search(r"tx\.origin|_incheck|_msgSender\(\)\s*==", c):
            flags.append("tampered OpenZeppelin ERC20")
            break
    return flags


def check_code(token):
    j = get_json(f"https://sourcify.dev/server/v2/contract/1/{token}?fields=sources")
    srcs = {p: v.get("content", "") for p, v in ((j or {}).get("sources") or {}).items()}
    if not srcs:
        if REQUIRE_SOURCE:
            return {"ok": False, "why": "source not on Sourcify (code unchecked)"}
        return {"ok": True, "flags": [], "note": "code unchecked"}
    flags = code_flags(srcs)
    socials = extract_socials("\n".join(srcs.values()))
    return {"ok": not flags, "why": ", ".join(flags), "flags": flags, "socials": socials}


def extract_socials(text):
    out = {}
    m = re.search(r"(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z0-9_+]+)", text)
    if m:
        out["tg"] = "https://t.me/" + m.group(1)
    m = re.search(r"(?:https?://)?(?:x\.com|twitter\.com)/([A-Za-z0-9_]+)", text)
    if m and m.group(1).lower() not in ("home", "intent", "share"):
        out["x"] = "https://x.com/" + m.group(1)
    m = re.search(r"https?://(?!t\.me|x\.com|twitter\.com|github\.com|docs\.|eips\.|forum\.|blog\.openzeppelin)([A-Za-z0-9.-]+\.[a-z]{2,})(/[^\s\"']*)?", text)
    if m:
        out["web"] = m.group(0)
    return out


def token_info(token):
    j = gt_get(f"tokens/{token}/info")
    a = ((j or {}).get("data") or {}).get("attributes") or {}
    soc = {}
    if a.get("telegram_handle"):
        soc["tg"] = "https://t.me/" + a["telegram_handle"]
    if a.get("twitter_handle"):
        soc["x"] = "https://x.com/" + a["twitter_handle"]
    if a.get("websites"):
        soc["web"] = a["websites"][0]
    if a.get("discord_url"):
        soc["discord"] = a["discord_url"]
    hold = a.get("holders") or {}
    return {
        "symbol": a.get("symbol") or "",
        "name": a.get("name") or "",
        "socials": soc,
        "top10": f((hold.get("distribution_percentage") or {}).get("top_10")),
        "holders": int(f(hold.get("count"))),
        "gt_score": f(a.get("gt_score")),
    }


# --------------------------------------------------------------------------
# 3) Telegram
# --------------------------------------------------------------------------


def tg_chat_id():
    global TG_CHAT
    if TG_CHAT or not TG_TOKEN:
        return TG_CHAT
    j = get_json(f"https://api.telegram.org/bot{TG_TOKEN}/getUpdates")
    for u in reversed((j or {}).get("result") or []):
        msg = u.get("message") or u.get("channel_post") or {}
        cid = (msg.get("chat") or {}).get("id")
        if cid:
            TG_CHAT = str(cid)
            log("auto-detected Telegram chat id", TG_CHAT, "- save it as TELEGRAM_CHAT_ID")
            return TG_CHAT
    return ""


def tg_send(text):
    if DRY_RUN or not TG_TOKEN:
        print("\n" + re.sub(r"<[^>]+>", "", text) + "\n")
        return True
    chat = tg_chat_id()
    if not chat:
        log("No Telegram chat id. Send any message to your bot first, then re-run.")
        return False
    try:
        r = session.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", json={
            "chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}, timeout=20)
        if r.status_code != 200:
            log("Telegram error", r.status_code, r.text[:200])
        return r.status_code == 200
    except requests.RequestException as e:
        log("Telegram error", e)
        return False


def money(x):
    return f"${x / 1e6:.2f}M" if x >= 1e6 else f"${x / 1e3:.1f}K"


def fmt_alert(c):
    r, gp, hp, info, code = c["row"], c["gp"], c["hp"], c["info"], c["code"]
    soc = {**(code.get("socials") or {}), **info["socials"]}
    sym = info["symbol"] or r["name"].split("/")[0].strip()
    lines = [
        f"🟢 <b>{escape(sym)}</b> — {escape(info['name'] or sym)}",
        f"<code>{r['token']}</code>",
        "",
        f"Age {age_hours(r['created']):.1f}h · FDV {money(r['cap'])} · Liq {money(r['liq'])}",
        f"Price 15m {r['m15']:+.1f}% · 1h {r['h1']:+.1f}% · 6h {r['h6']:+.1f}%",
        f"Buyers/sellers 1h {r['buyers1']}/{r['sellers1']} · 6h {r['buyers6']}/{r['sellers6']}",
        f"Buys/sells 15m {r['b15']}/{r['s15']} · Vol 1h {money(r['vol1'])}",
        "",
        f"✅ Sells OK (sim {hp.get('holders_sim', 0)} holders) · tax {hp.get('buy', 0):.0f}/{hp.get('sell', 0):.0f}%",
        f"✅ LP {gp['lp_safe']:.0f}% locked/burned{(' (' + escape(gp['lock_tag']) + ')') if gp.get('lock_tag') else ''} · owner {'renounced' if gp['renounced'] else 'ACTIVE'}",
        f"✅ Code: no backdoor patterns" if not code.get("note") else f"⚠️ Code: {code['note']}",
        f"Holders {max(gp['holders'], info['holders'])} · top wallet {gp['top_wallet']:.1f}% · top10 {info['top10']:.0f}%",
    ]
    if soc:
        lines.append("Socials: " + " · ".join(f'<a href="{escape(v)}">{k}</a>' for k, v in soc.items()))
    else:
        lines.append("Socials: none")
    lines += [
        "",
        f'<a href="https://dexscreener.com/ethereum/{r["token"]}">Chart</a> · '
        f'<a href="https://etherscan.io/token/{r["token"]}#code">Code</a> · '
        f'<a href="https://etherscan.io/token/{r["token"]}#balances">Holders</a>',
        "<i>Automated checks only — not advice. LP lock expiry and wallet clusters not checked.</i>",
    ]
    return "\n".join(lines)


def escape(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def load_state():
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_state(st):
    cutoff = time.time() - 7 * 86400
    st = {k: v for k, v in st.items() if v.get("t", 0) > cutoff}
    with open(STATE_FILE, "w") as fh:
        json.dump(st, fh, indent=0, sort_keys=True)


def main():
    state = load_state()
    rows = scan_pools()

    # best pool per token
    best = {}
    for r in rows:
        if activity_ok(r):
            if r["token"] not in best or r["buyers1"] > best[r["token"]]["buyers1"]:
                best[r["token"]] = r
    cands = sorted(best.values(), key=lambda r: (r["buyers1"] - r["sellers1"], r["vol1"]), reverse=True)
    log(f"{len(cands)} coins pass activity filters")

    now = time.time()
    passed, rejected = [], []
    for r in cands[:15]:
        tok = r["token"]
        seen = state.get(tok)
        if seen and now - seen.get("t", 0) < REALERT_HOURS * 3600:
            log("skip (already alerted)", r["name"])
            continue
        hp = check_honeypot(tok)
        if not hp["ok"]:
            rejected.append((r, hp["why"]))
            continue
        gp = check_goplus(tok, r["pool"])
        if not gp["ok"]:
            rejected.append((r, gp["why"]))
            continue
        code = check_code(tok)
        if not code["ok"]:
            rejected.append((r, code["why"]))
            continue
        info = token_info(tok)
        has_soc = bool(info["socials"] or code.get("socials"))
        if REQUIRE_SOCIALS and not has_soc:
            rejected.append((r, "no socials"))
            continue
        passed.append({"row": r, "hp": hp, "gp": gp, "code": code, "info": info, "soc": has_soc})

    for r, why in rejected:
        log("REJECT", r["name"], r["token"], "-", why)

    # socials first, then net buyers
    passed.sort(key=lambda c: (c["soc"], c["row"]["buyers1"] - c["row"]["sellers1"]), reverse=True)
    sent = 0
    for c in passed[:MAX_ALERTS]:
        if tg_send(fmt_alert(c)):
            state[c["row"]["token"]] = {"t": now, "name": c["row"]["name"]}
            sent += 1
    log(f"alerts sent: {sent} (passed {len(passed)}, rejected {len(rejected)})")

    if os.environ.get("HEARTBEAT", "").lower() in ("1", "true") and sent == 0:
        tg_send(f"Scan done {datetime.now(timezone.utc):%H:%M} UTC — {len(rows)} pools, "
                f"{len(cands)} active, 0 passed safety. Rejected: " +
                ", ".join(f"{escape(r['name'].split('/')[0].strip())} ({escape(w)})" for r, w in rejected[:5]))
    save_state(state)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test-telegram":
        print("ok" if tg_send("✅ ETH gem bot is connected.") else "failed")
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        tok = sys.argv[2].lower()
        print(json.dumps({"honeypot": check_honeypot(tok), "goplus": check_goplus(tok, ""),
                          "code": check_code(tok)}, indent=2))
        sys.exit(0)
    main()
