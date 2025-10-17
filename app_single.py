#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MyAddon — FastAPI single-file server (modern admin UI)
- JSON DB (DB_PATH or ./db.json)
- ADMIN_TOKEN from env or default
- Hidden token (password field), no token in URL
- Accurate online counter (last_seen window)
- Keys: multiline input (one per line) or auto-generate if empty
- Edit user ID + migrate keys.used_by
- Bulk zero with confirmation + backup/undo
Run local:
    uvicorn app_single:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from pydantic import BaseModel
from datetime import datetime, timezone
import os, json, re, secrets, shutil

APP_TITLE = "MyAddon Server"
DB_FILE   = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "db.json"))
ADMIN_TOKEN_ENV = os.getenv("ADMIN_TOKEN")  # يغلب الافتراضي إن وُجد

# نافذة حساب "أونلاين" بالثواني (5 دقائق)
ONLINE_WINDOW_SEC = 300

app = FastAPI(title=APP_TITLE)

# ------------------------------ DB Layer ------------------------------
DEFAULT_DB = {
    "globals": {
        "free_mode": False,
        "lockdown": False,
        "online": 0,
        # التوكن الافتراضي — يفضّل ضبط ADMIN_TOKEN في Render
        "admin_token": "202426933Ibrahim",
    },
    "users": {},
    "keys": {},
    "admins": {}
}

def now_ts() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())

def db_dir() -> str:
    return os.path.dirname(DB_FILE) or "."

def save_db(db: dict) -> None:
    os.makedirs(db_dir(), exist_ok=True)
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_FILE)

def load_db() -> dict:
    if not os.path.exists(DB_FILE):
        initial = json.loads(json.dumps(DEFAULT_DB))
        if ADMIN_TOKEN_ENV:
            initial["globals"]["admin_token"] = ADMIN_TOKEN_ENV
        save_db(initial)
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def backup_db() -> str:
    """يعمل نسخة احتياطية قبل عمليات جذرية (تُستخدم للـUndo)."""
    os.makedirs(db_dir(), exist_ok=True)
    bak = DB_FILE + ".bak"
    shutil.copy2(DB_FILE, bak) if os.path.exists(DB_FILE) else save_db(DEFAULT_DB)
    return bak

def restore_backup() -> bool:
    bak = DB_FILE + ".bak"
    if os.path.exists(bak):
        shutil.copy2(bak, DB_FILE)
        return True
    return False

def ensure_user(db: dict, uid: str) -> dict:
    u = db["users"].get(uid)
    if not u:
        u = {
            "id": uid,
            "expires_at": 0,
            "unlimited": False,
            "devices": 1,
            "hwids": [],
            "banned": False,
            "role": "user",
            "last_seen": 0,
        }
        db["users"][uid] = u
    return u

def pretty_duration_from_secs(secs: int) -> str:
    if secs <= 0: return "0 ثانية"
    mins = secs // 60
    hrs  = mins // 60
    days = hrs // 24
    if days > 0: return f"{days} يوم {hrs%24} ساعة"
    if hrs  > 0: return f"{hrs} ساعة {mins%60} دقيقة"
    if mins > 0: return f"{mins} دقيقة"
    return f"{secs} ثانية"

def minutes_from_unit(amount: int, unit: str) -> int:
    unit = unit.lower()
    if unit in ("m","minute","minutes","د","دقيقة","دقائق"): return amount
    if unit in ("h","hour","hours","س","ساعة","ساعات"):      return amount * 60
    if unit in ("d","day","days","ي","يوم","أيام","ايام"):   return amount * 60 * 24
    if unit in ("mo","mon","month","months","ش","شهر","شهور"): return amount * 60 * 24 * 30
    raise ValueError("وحدة غير صحيحة")

KEY_RE = re.compile(r"^[A-Z0-9]{4,6}(?:-[A-Z0-9]{4,6}){0,3}$", re.I)

def _compute_online(db: dict, window_seconds: int = ONLINE_WINDOW_SEC) -> int:
    now = now_ts()
    return sum(1 for u in db.get("users", {}).values()
               if now - int(u.get("last_seen", 0)) <= window_seconds)

# ------------------------------ API (used by client) ------------------------------
class KeyActivateReq(BaseModel):
    id: str
    hwid: str | None = ""
    key: str

@app.get("/api/check")
def api_check(id: str = "", hwid: str = ""):
    db = load_db()
    g  = db["globals"]

    resp = {
        "ok": False,
        "banned": False,
        "lockdown": bool(g.get("lockdown", False)),
        "free_mode": bool(g.get("free_mode", False)),
        "unlimited": False,
        "remain": 0,
        "online": 0
    }

    # إقفال مؤقت
    if g.get("lockdown", False):
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    u = db["users"].get(id) if id else None

    # محظور؟
    if u and u.get("banned", False):
        resp["banned"] = True
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # وضع مجاني للجميع
    if g.get("free_mode", False):
        resp["ok"] = True
        if id:
            u = ensure_user(db, id)
            # ربط HWID إن وُجد وتحت حد الأجهزة
            if hwid:
                hwids = list(u.get("hwids", []))
                if hwid not in hwids and len(hwids) < int(u.get("devices",1)):
                    hwids.append(hwid)
                    u["hwids"] = hwids
            u["last_seen"] = now_ts()
            db["users"][id] = u
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # لا يملك اشتراك
    if not u:
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # ربط HWID ضمن حد الأجهزة
    dev_limit = int(u.get("devices", 1))
    hwids = list(u.get("hwids", []))
    if hwid and hwid not in hwids and len(hwids) < dev_limit:
        hwids.append(hwid)
        u["hwids"] = hwids

    # تجاوز الحد
    if len(u.get("hwids", [])) > dev_limit:
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # تحديث آخر ظهور
    u["last_seen"] = now_ts()

    # غير محدود؟
    if u.get("unlimited", False):
        resp["ok"] = True
        resp["unlimited"] = True
    else:
        remain = int(u.get("expires_at", 0)) - now_ts()
        if remain > 0:
            resp["ok"] = True
            resp["remain"] = remain

    db["users"][u["id"]] = u
    g["online"] = _compute_online(db)
    save_db(db)
    resp["online"] = g["online"]
    return JSONResponse(resp)

@app.post("/api/activate/key")
def api_activate_by_key(req: KeyActivateReq):
    db = load_db()
    g  = db["globals"]

    if g.get("lockdown", False):
        return JSONResponse({"ok": False, "msg": "lockdown"})

    if not KEY_RE.match(req.key):
        return JSONResponse({"ok": False, "msg": "bad key format"})

    key = db.get("keys", {}).get(req.key)
    if not key:
        return JSONResponse({"ok": False, "msg": "key not found"})

    if key.get("single_use", True) and key.get("used_by"):
        return JSONResponse({"ok": False, "msg": "key already used"})

    u = ensure_user(db, req.id)
    if u.get("banned", False):
        return JSONResponse({"ok": False, "msg": "banned"})

    # حد الأجهزة
    u["devices"] = max(1, int(key.get("devices", 1)))

    # ربط HWID
    if req.hwid and req.hwid not in u["hwids"]:
        if len(u["hwids"]) < u["devices"]:
            u["hwids"].append(req.hwid)

    if key.get("unlimited", False):
        u["unlimited"] = True
        u["expires_at"] = 0
    else:
        add_min = int(key.get("minutes", 0))
        base = max(now_ts(), int(u.get("expires_at", 0)))
        u["expires_at"] = base + add_min * 60
        u["unlimited"] = False

    if key.get("single_use", True):
        key["used_by"] = req.id

    db["keys"][key["code"]] = key
    db["users"][u["id"]] = u
    save_db(db)
    return JSONResponse({"ok": True, "msg": "activated"})

# ------------------------------ Admin helpers + UI ------------------------------
def require_admin(db: dict, token: str | None, level: str = "viewer"):
    need = db["globals"].get("admin_token", "admin")
    if need and token != need:
        raise HTTPException(403, "bad admin token")
    return True

def html_shell(title: str, body: str) -> HTMLResponse:
    page = f"""<!doctype html>
<html dir="rtl" lang="ar"><head>
<meta charset="utf-8"/>
<title>{title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
:root {{
  --bg:#0b0d10; --panel:#0f141a; --panel2:#0b1015; --border:#1f2a36;
  --text:#e6edf3; --muted:#9fb3c8; --accent:#ffd28a; --link:#7cc8ff;
  --ok:#3ddc97; --bad:#ff8a8a; --btn:#161b22; --btnb:#2d3947;
}}
*{{box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:Segoe UI,Arial;margin:16px}}
a{{color:var(--link)}}
h1,h2{{color:var(--accent);margin:8px 0 10px}}
.card{{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);border-radius:14px;padding:14px;margin:10px 0}}
.topbar{{position:sticky;top:0;z-index:10;background:var(--bg);padding-bottom:8px;margin-bottom:10px;border-bottom:1px solid var(--border)}}
.badge{{background:#0d1b26;border:1px solid var(--border);border-radius:999px;padding:6px 10px;color:var(--text);display:inline-flex;gap:6px;align-items:center}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}}
label{{display:inline-block;margin:4px 0}}
input,select,button,textarea{{background:var(--btn);color:var(--text);border:1px solid var(--btnb);border-radius:10px;padding:8px}}
button{{cursor:pointer}}
button.primary{{background:#1f2a36;border-color:#3b4c61}}
button.danger{{background:#2a1515;border-color:#703939;color:#ffbdbd}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{border:1px solid var(--border);padding:6px;text-align:center}}
.small{{font-size:12px;color:var(--muted)}}
.ok{{color:var(--ok)}} .bad{{color:var(--bad)}}
.pwwrap{{display:flex;align-items:center;gap:8px}}
hr{{border:0;border-top:1px solid var(--border);margin:16px 0}}
.codebox{{font-family:Consolas,monospace;font-size:12px;background:#0b1218;padding:10px;border-radius:10px;border:1px dashed var(--border)}}
</style>
<script>
function wireToken(){{
  const pw = document.getElementById('admintoken');
  function inject(form){{
    if(!pw) return true;
    const h = form.querySelector('input[name=token]');
    if(h) h.value = pw.value;
    return true;
  }}
  document.querySelectorAll('form').forEach(f=>{{
    f.addEventListener('submit', ()=>inject(f));
  }});
  const tgl=document.getElementById('togglepw');
  if(tgl && pw){{
    tgl.addEventListener('click', ()=>{
      pw.type = (pw.type==='password'?'text':'password');
      tgl.textContent = (pw.type==='password'?'إظهار':'إخفاء');
    });
  }}
}}
window.addEventListener('DOMContentLoaded', wireToken);
</script>
</head><body>
{body}
</body></html>"""
    return HTMLResponse(page)

def render_users_table(db: dict, only_active=False, only_banned=False) -> str:
    rows = []
    now = now_ts()
    for u in db["users"].values():
        if only_banned and not u.get("banned", False):
            continue
        if only_active:
            active = u.get("unlimited") or (int(u.get("expires_at",0)) > now)
            if not active: 
                continue
        remain = "غير محدود" if u.get("unlimited") else pretty_duration_from_secs(max(0, int(u.get("expires_at",0))-now))
        rows.append(
            f"<tr><td>{u['id']}</td>"
            f"<td>{remain}</td>"
            f"<td>{u.get('devices',1)}</td>"
            f"<td class='small'>{','.join(u.get('hwids',[])) or '-'}</td>"
            f"<td>{'نعم' if u.get('banned') else 'لا'}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan=5>لا يوجد</td></tr>")
    return "<table><tr><th>ID</th><th>المدة</th><th>الأجهزة</th><th>HWIDs</th><th>محظور؟</th></tr>" + "".join(rows) + "</table>"

def render_keys_table(db: dict) -> str:
    rows = []
    for k in db.get("keys", {}).values():
        mins = int(k.get("minutes",0))
        dur  = "غير محدود" if k.get("unlimited") else pretty_duration_from_secs(mins*60)
        rows.append(
            f"<tr><td>{k['code']}</td>"
            f"<td>{dur}</td>"
            f"<td>{k.get('devices',1)}</td>"
            f"<td>{'مرة واحدة' if k.get('single_use',True) else 'متكرر'}</td>"
            f"<td class='small'>{k.get('used_by') or '-'}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan=5>لا يوجد مفاتيح</td></tr>")
    return "<table><tr><th>الكود</th><th>المدة</th><th>الأجهزة</th><th>الاستخدام</th><th>Used By</th></tr>" + "".join(rows) + "</table>"

def gbadge(db: dict) -> str:
    g = db["globals"]
    return (f"<div class='badge'>"
            f"<span>أونلاين (تقريبي): <b>{g.get('online',0)}</b></span>"
            f"</div>")

# ------------------------------ Admin HOME ------------------------------
@app.get("/", response_class=HTMLResponse)
def admin_home():
    db = load_db()
    g  = db["globals"]

    top = (
        "<div class='topbar'>"
        "<h1 style='margin:6px 0'>لوحة إدارة — MyAddon</h1>"
        f"{gbadge(db)}"
        "</div>"
    )

    token_bar = (
        "<div class='card'>"
        "<div class='pwwrap'>"
        "التوكن: <input id='admintoken' type='password' placeholder='أدخل التوكن هنا' style='width:260px' autocomplete='off'>"
        "<button type='button' id='togglepw'>إظهار</button>"
        "</div>"
        "<div class='small'>لن يُعرض التوكن في الرابط، ويتم حقنه تلقائيًا داخل الاستمارات عند الإرسال.</div>"
        "</div>"
    )

    toggles = (
        "<div class='card'>"
        "<h2>تحكم عام</h2>"
        "<form method='post' action='/toggle'>"
        "<input type='hidden' name='token' value=''>"
        f"<button class='primary' name='what' value='free'>{'إيقاف' if g.get('free_mode') else 'تشغيل'} الوضع المجاني</button> "
        f"<button class='primary' name='what' value='lock'>{'فتح' if g.get('lockdown') else 'إغلاق'} عن الكل</button> "
        "</form>"
        "</div>"
    )

    activate_id = (
        "<div class='card'>"
        "<h2>تفعيل مباشر عبر ID</h2>"
        "<form method='post' action='/admin/activate_id'>"
        "<input type='hidden' name='token' value=''>"
        "ID: <input name='id' required style='width:160px'> "
        "قيمة: <input name='amount' value='30' style='width:70px'> "
        "وحدة: <select name='unit'>"
        "<option value='m'>دقائق</option><option value='h'>ساعات</option>"
        "<option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "أجهزة: <input name='devices' value='1' style='width:60px'> "
        "غير محدود؟ <input type='checkbox' name='unlimited'> "
        "<button class='primary'>تفعيل/تعديل</button>"
        "</form>"
        "</div>"
    )

    keys_box = (
        "<div class='card'>"
        "<h2>مفاتيح — إضافة/إدارة</h2>"
        "<form method='post' action='/admin/create_keys'>"
        "<input type='hidden' name='token' value=''>"
        "<div class='small'>سطر لكل كود. اترك الحقل فارغًا لتوليد كود واحد تلقائيًا.</div>"
        "<textarea name='codes' placeholder='ABCD-1234-EEEE-5678&#10;WXYZ-0000-9999-ABCD'></textarea>"
        "<div style='margin-top:8px'>"
        "قيمة: <input name='amount' value='60' style='width:70px'> "
        "وحدة: <select name='unit'><option value='m'>دقائق</option><option value='h'>ساعات</option><option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "أجهزة: <input name='devices' value='1' style='width:60px'> "
        "غير محدود؟ <input type='checkbox' name='unlimited'> "
        "مرّة واحدة؟ <input type='checkbox' name='single_use' checked> "
        "<button class='primary'>حفظ</button>"
        "</div>"
        "</form>"
        "<hr>"
        f"{render_keys_table(db)}"
        "<div style='margin-top:8px'>"
        "<form method='post' action='/admin/delete_key' style='display:inline-block'>"
        "<input type='hidden' name='token' value=''>"
        "حذف كود: <input name='code' placeholder='ABCD-1234' style='width:180px'> "
        "<button class='danger'>حذف</button>"
        "</form> "
        "<form method='post' action='/admin/edit_key' style='display:inline-block;margin-inline-start:10px'>"
        "<input type='hidden' name='token' value=''>"
        "تعديل كود: <input name='code' placeholder='ABCD-1234' style='width:180px'> "
        "قيمة: <input name='amount' value='60' style='width:70px'> "
        "<select name='unit'><option value='m'>دقائق</option><option value='h'>ساعات</option><option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "أجهزة: <input name='devices' value='1' style='width:60px'> "
        "غير محدود؟ <input type='checkbox' name='unlimited'> "
        "مرّة واحدة؟ <input type='checkbox' name='single_use'> "
        "<button class='primary'>تعديل</button>"
        "</form>"
        "</div>"
        "</div>"
    )

    user_tools = (
        "<div class='card'>"
        "<h2>بحث/قوائم</h2>"
        "<form method='get' action='/admin/user' style='margin-bottom:10px'>"
        "ID: <input name='id' style='width:160px'> "
        "<button class='primary'>فتح</button>"
        "</form>"
        "<div class='grid'>"
        f"<div><div class='small'>مشتركين (نشطين):</div>{render_users_table(db, only_active=True)}</div>"
        f"<div><div class='small'>محظورين:</div>{render_users_table(db, only_banned=True)}</div>"
        "</div>"
        "</div>"
    )

    bulk = (
        "<div class='card'>"
        "<h2>عمليات جماعية (خطر)</h2>"
        "<div class='small'>قبل التصفير تُنشأ نسخة احتياطية، ويمكن الرجوع لها.</div>"
        "<form method='post' action='/admin/bulk_zero' class='confirm' style='padding:10px;margin-top:8px;border-radius:10px'>"
        "<input type='hidden' name='token' value=''>"
        "اكتب <b>ZERO</b> للتأكيد: <input name='confirm' placeholder='ZERO' style='width:120px'> "
        "<button class='danger'>تصفير مدة الجميع</button>"
        "</form>"
        "<form method='post' action='/admin/bulk_undo' style='margin-top:8px'>"
        "<input type='hidden' name='token' value=''>"
        "<button class='primary'>تراجع (استرجاع النسخة الاحتياطية)</button>"
        "</form>"
        "</div>"
    )

    body = top + token_bar + toggles + activate_id + keys_box + user_tools + bulk
    return html_shell("لوحة الإدارة", body)

# ------------------------------ Admin actions ------------------------------
@app.post("/toggle")
def admin_toggle(what: str = Form(...), token: str = Form("")):
    db = load_db()
    require_admin(db, token, "admin")
    if what == "free":
        db["globals"]["free_mode"] = not db["globals"].get("free_mode", False)
    elif what == "lock":
        db["globals"]["lockdown"] = not db["globals"].get("lockdown", False)
    save_db(db)
    return RedirectResponse(url="/", status_code=302)

@app.post("/admin/create_keys")
def admin_create_keys(
    token: str = Form(""),
    codes: str = Form(""),
    amount: int = Form(60),
    unit: str = Form("m"),
    devices: int = Form(1),
    unlimited: str = Form(None),
    single_use: str = Form("on"),
):
    db = load_db()
    require_admin(db, token, "admin")
    minutes = 0 if unlimited else minutes_from_unit(amount, unit)

    # فك الأكواد من textarea
    codes = codes.strip()
    created = []
    if not codes:
        parts = [secrets.token_hex(2).upper() for _ in range(4)]
        code = "-".join(parts)
        created.append(code)
    else:
        for line in codes.splitlines():
            line = line.strip().upper()
            if not line:
                parts = [secrets.token_hex(2).upper() for _ in range(4)]
                line = "-".join(parts)
            created.append(line)

    db.setdefault("keys", {})
    for code in created:
        if not KEY_RE.match(code):
            continue
        db["keys"][code] = {
            "code": code,
            "minutes": minutes,
            "devices": max(1,int(devices)),
            "unlimited": bool(unlimited),
            "single_use": (single_use is not None),
            "used_by": None
        }
    save_db(db)
    return RedirectResponse(url="/", status_code=302)

@app.post("/admin/delete_key")
def admin_delete_key(token: str = Form(""), code: str = Form(...)):
    db = load_db()
    require_admin(db, token, "admin")
    code = code.upper()
    if code in db.get("keys", {}):
        del db["keys"][code]
        save_db(db)
        return RedirectResponse(url="/", status_code=302)
    return PlainTextResponse("لم يتم العثور على الكود", status_code=404)

@app.post("/admin/edit_key")
def admin_edit_key(
    token: str = Form(""),
    code: str = Form(...),
    amount: int = Form(60),
    unit: str = Form("m"),
    devices: int = Form(1),
    unlimited: str = Form(None),
    single_use: str = Form(None),
):
    db = load_db()
    require_admin(db, token, "admin")
    code = code.upper()
    key = db.get("keys", {}).get(code)
    if not key:
        return PlainTextResponse("لم يتم العثور على الكود", status_code=404)
    minutes = 0 if unlimited else minutes_from_unit(amount, unit)
    key["minutes"]   = minutes
    key["devices"]   = max(1, int(devices))
    key["unlimited"] = bool(unlimited)
    key["single_use"]= (single_use is not None)
    db["keys"][code] = key
    save_db(db)
    return RedirectResponse(url="/", status_code=302)

# صفحة مستخدم
@app.get("/admin/user", response_class=HTMLResponse)
def admin_get_user(id: str):
    db = load_db()
    u = db["users"].get(id)
    if not u:
        body = (
            "<div class='topbar'><h1>المستخدم</h1></div>"
            "<div class='card'>لا يوجد مستخدم بهذا الـID.</div>"
            "<div class='card'><a href='/'>رجوع</a></div>"
        )
        return html_shell("المستخدم", body)

    remain = "غير محدود" if u.get("unlimited") else pretty_duration_from_secs(max(0, int(u.get("expires_at",0))-now_ts()))
    pwbar = (
        "<div class='card'>"
        "<div class='pwwrap'>"
        "التوكن: <input id='admintoken' type='password' placeholder='أدخل التوكن هنا' style='width:260px' autocomplete='off'>"
        "<button type='button' id='togglepw'>إظهار</button>"
        "</div>"
        "<div class='small'>لن يُعرض التوكن في الرابط، ويتم حقنه تلقائيًا داخل الاستمارات.</div>"
        "</div>"
    )
    info = (
        "<div class='card'>"
        f"<h2>المستخدم: {id}</h2>"
        f"<div>المدة: <b>{remain}</b></div>"
        f"<div>الأجهزة: <b>{u.get('devices',1)}</b></div>"
        f"<div>HWIDs: <span class='small'>{','.join(u.get('hwids',[])) or '-'}</span></div>"
        f"<div>محظور؟ <b>{'نعم' if u.get('banned') else 'لا'}</b></div>"
        "</div>"
    )
    forms = (
        "<div class='grid'>"
        "<div class='card'>"
        "<h2>زيادة/تنقيص الوقت</h2>"
        "<form method='post' action='/admin/adjust_time'>"
        "<input type='hidden' name='token' value=''>"
        f"<input type='hidden' name='id' value='{id}'>"
        "قيمة: <input name='amount' value='30' style='width:70px'> "
        "وحدة: <select name='unit'><option value='m'>دقائق</option><option value='h'>ساعات</option><option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "<button class='primary' name='op' value='add'>زيادة</button> "
        "<button class='primary' name='op' value='sub'>تنقيص</button>"
        "</form>"
        "</div>"
        "<div class='card'>"
        "<h2>تعديل حد الأجهزة</h2>"
        "<form method='post' action='/admin/set_devices'>"
        "<input type='hidden' name='token' value=''>"
        f"<input type='hidden' name='id' value='{id}'>"
        f"حد الأجهزة: <input name='devices' value='{u.get('devices',1)}' style='width:80px'> "
        "<button class='primary'>حفظ</button>"
        "</form>"
        "</div>"
        "<div class='card'>"
        "<h2>غير محدود</h2>"
        "<form method='post' action='/admin/set_unlimited'>"
        "<input type='hidden' name='token' value=''>"
        f"<input type='hidden' name='id' value='{id}'>"
        f"غير محدود؟ <input type='checkbox' name='unlimited' {'checked' if u.get('unlimited') else ''}> "
        "<button class='primary'>تحديث</button>"
        "</form>"
        "</div>"
        "<div class='card'>"
        "<h2>تغيير الـID</h2>"
        "<form method='post' action='/admin/change_id'>"
        "<input type='hidden' name='token' value=''>"
        f"<input type='hidden' name='old_id' value='{id}'>"
        "ID جديد: <input name='new_id' placeholder='ID جديد' style='width:180px' required> "
        "<button class='primary'>تغيير</button>"
        "</form>"
        "<div class='small'>يتم نقل الاشتراك وHWIDs وتحديث المفاتيح المستخدمة.</div>"
        "</div>"
        "<div class='card'>"
        "<h2>حظر/فك الحظر</h2>"
        "<form method='post' action='/admin/ban' style='display:inline-block'>"
        "<input type='hidden' name='token' value=''>"
        f"<input type='hidden' name='id' value='{id}'>"
        "<button class='danger'>حظر</button>"
        "</form> "
        "<form method='post' action='/admin/unban' style='display:inline-block;margin-inline-start:10px'>"
        "<input type='hidden' name='token' value=''>"
        f"<input type='hidden' name='id' value='{id}'>"
        "<button class='primary'>فك الحظر</button>"
        "</form>"
        "</div>"
        "</div>"
        "<div class='card'><a href='/'>&larr; رجوع</a></div>"
    )
    return html_shell("المستخدم", pwbar + info + forms)

@app.post("/admin/activate_id")
def admin_activate_id(
    token: str = Form(""),
    id: str = Form(...),
    amount: int = Form(30),
    unit: str = Form("m"),
    devices: int = Form(1),
    unlimited: str = Form(None),
):
    db = load_db()
    require_admin(db, token, "activator")
    u = ensure_user(db, id)
    u["devices"] = max(1, int(devices))
    if unlimited:
        u["unlimited"] = True
        u["expires_at"] = 0
    else:
        mins = minutes_from_unit(amount, unit)
        base = max(now_ts(), int(u.get("expires_at", 0)))
        u["expires_at"] = base + mins*60
        u["unlimited"] = False
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}", status_code=302)

@app.post("/admin/adjust_time")
def admin_adjust_time(
    token: str = Form(""),
    id: str = Form(...),
    amount: int = Form(...),
    unit: str = Form("m"),
    op: str = Form("add")
):
    db = load_db()
    require_admin(db, token, "activator")
    u = ensure_user(db, id)
    if u.get("unlimited"):
        return RedirectResponse(url=f"/admin/user?id={id}", status_code=302)
    mins = minutes_from_unit(amount, unit)
    cur = max(0, int(u.get("expires_at",0)))
    if op == "add":
        base = max(now_ts(), cur)
        u["expires_at"] = base + mins*60
    else:
        u["expires_at"] = max(0, cur - mins*60)
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}", status_code=302)

@app.post("/admin/set_devices")
def admin_set_devices(token: str = Form(""), id: str = Form(...), devices: int = Form(...)):
    db = load_db()
    require_admin(db, token, "activator")
    u = ensure_user(db, id)
    u["devices"] = max(1, int(devices))
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}", status_code=302)

@app.post("/admin/set_unlimited")
def admin_set_unlimited(token: str = Form(""), id: str = Form(...), unlimited: str | None = Form(None)):
    db = load_db()
    require_admin(db, token, "activator")
    u = ensure_user(db, id)
    if unlimited:
        u["unlimited"] = True
        u["expires_at"] = 0
    else:
        u["unlimited"] = False
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}", status_code=302)

@app.post("/admin/change_id")
def admin_change_id(token: str = Form(""), old_id: str = Form(...), new_id: str = Form(...)):
    db = load_db()
    require_admin(db, token, "admin")
    old_id = old_id.strip()
    new_id = new_id.strip()
    if not new_id or new_id in db["users"]:
        return PlainTextResponse("ID غير صالح أو موجود مسبقًا", status_code=400)
    u = db["users"].pop(old_id, None)
    if not u:
        return PlainTextResponse("المستخدم غير موجود", status_code=404)
    u["id"] = new_id
    db["users"][new_id] = u
    # تحديث المفاتيح المستخدمة
    for k in db.get("keys", {}).values():
        if k.get("used_by") == old_id:
            k["used_by"] = new_id
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={new_id}", status_code=302)

@app.post("/admin/ban")
def admin_ban(token: str = Form(""), id: str = Form(...)):
    db = load_db()
    require_admin(db, token, "admin")
    u = ensure_user(db, id)
    u["banned"] = True
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}", status_code=302)

@app.post("/admin/unban")
def admin_unban(token: str = Form(""), id: str = Form(...)):
    db = load_db()
    require_admin(db, token, "admin")
    u = ensure_user(db, id)
    u["banned"] = False
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}", status_code=302)

@app.post("/admin/bulk_zero")
def admin_bulk_zero(token: str = Form(""), confirm: str = Form("")):
    db = load_db()
    require_admin(db, token, "admin")
    if confirm.strip().upper() != "ZERO":
        return PlainTextResponse("لم يتم التأكيد. اكتب ZERO.", status_code=400)
    backup_db()
    for u in db.get("users", {}).values():
        u["unlimited"] = False
        u["expires_at"] = 0
    save_db(db)
    return RedirectResponse(url="/", status_code=302)

@app.post("/admin/bulk_undo")
def admin_bulk_undo(token: str = Form("")):
    db = load_db()
    require_admin(db, token, "admin")
    if restore_backup():
        return RedirectResponse(url="/", status_code=302)
    return PlainTextResponse("لا توجد نسخة احتياطية", status_code=404)

# ------------------------------ Health ------------------------------
@app.get("/health")
def health():
    return {"ok": True}

# ------------------------------ Local dev runner ------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app_single:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
