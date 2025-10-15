#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MyAddon FastAPI license server (single-file, fixed)
- تخزين JSON في DB_PATH أو db.json
- ADMIN_TOKEN من متغير بيئة
- لوحة إدارة داكنة + عدّاد أونلاين
تشغيل محلي:
    uvicorn app_single:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from pydantic import BaseModel
from datetime import datetime, timezone
import os, json, re, secrets

APP_TITLE = "MyAddon Server (Single)"
DB_FILE   = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "db.json"))
ADMIN_TOKEN_ENV = os.getenv("ADMIN_TOKEN")  # يغلب القيمة الافتراضية عند الإنشاء

app = FastAPI(title=APP_TITLE)

# ------------------------------ DB Layer ------------------------------
DEFAULT_DB = {
    "globals": {
        "free_mode": False,
        "lockdown": False,
        "online": 0,
        "admin_token": "admin",
    },
    "users": {},
    "keys": {},
    "admins": {}
}

def now_ts() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())

def save_db(db: dict) -> None:
    tmp = DB_FILE + ".tmp"
    os.makedirs(os.path.dirname(DB_FILE) or ".", exist_ok=True)
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

def _compute_online(db: dict, window_seconds: int = 300) -> int:
    now = now_ts()
    cnt = 0
    for u in db.get("users", {}).values():
        if now - int(u.get("last_seen", 0)) <= window_seconds:
            cnt += 1
    return cnt

# ------------------------------ API used by AHK ------------------------------
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

    # lockdown: منع فوري مع تحديث الأونلاين
    if g.get("lockdown", False):
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # إن كان معرفًا
    u = db["users"].get(id) if id else None

    # محظور؟
    if u and u.get("banned", False):
        resp["banned"] = True
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # free_mode يسمح للجميع (غير المحظورين)
    if g.get("free_mode", False):
        resp["ok"] = True
        if id:
            u = ensure_user(db, id)
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

    # ليس لديه اشتراك
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
        db["users"][id] = u

    # تجاوز الحد
    if len(u.get("hwids", [])) > dev_limit:
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # آخر ظهور
    u["last_seen"] = now_ts()
    db["users"][id] = u

    # غير محدود
    if u.get("unlimited", False):
        resp["ok"] = True
        resp["unlimited"] = True
        g["online"] = _compute_online(db)
        save_db(db)
        resp["online"] = g["online"]
        return JSONResponse(resp)

    # وقت متبقّي
    remain = int(u.get("expires_at", 0)) - now_ts()
    if remain > 0:
        resp["ok"] = True
        resp["remain"] = remain

    g["online"] = _compute_online(db)
    db["globals"]["online"] = g["online"]
    save_db(db)
    resp["online"] = g["online"]
    return JSONResponse(resp)

class KeyActivateReq(BaseModel):
    id: str
    hwid: str | None = ""
    key: str

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
    devices = int(key.get("devices", 1))
    u["devices"] = max(1, devices)

    # ربط HWID
    if req.hwid and req.hwid not in u["hwids"]:
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

# ------------------------------ Admin helpers ------------------------------
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
<style>
:root {{ --bg:#0b0b0b; --panel:#101010; --border:#2a2a2a; --text:#eaeaea; --accent:#ffd28a; --link:#7cc8ff; }}
body{{background:var(--bg);color:var(--text);font-family:Segoe UI,Arial;margin:20px}}
h1,h2{{color:var(--accent)}}
input,select,button,textarea{{background:#111;color:#fff;border:1px solid var(--border);border-radius:8px;padding:6px}}
a{{color:var(--link)}}
hr{{border:0;border-top:1px solid var(--border);margin:18px 0}}
.box{{border:1px solid var(--border);border-radius:12px;padding:12px;margin:10px 0;background:var(--panel)}}
.small{{font-size:12px;opacity:.8}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid var(--border);padding:6px;text-align:center}}
.ok{{color:#51e351}} .bad{{color:#ff8a8a}}
.topbar{{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-bottom:10px}}
.badge{{background:#1a1a1a;border:1px solid var(--border);border-radius:999px;padding:6px 10px}}
</style></head><body>
{body}
</body></html>"""
    return HTMLResponse(page)

def render_users_table(db: dict, only_active=False, only_banned=False) -> str:
    rows = []
    for u in db["users"].values():
        if only_active:
            active = u.get("unlimited") or (u.get("expires_at",0) > now_ts())
            if not active: 
                continue
        if only_banned and not u.get("banned", False):
            continue
        remain = "غير محدود" if u.get("unlimited") else pretty_duration_from_secs(max(0, u.get("expires_at",0)-now_ts()))
        rows.append(
            f"<tr><td>{u['id']}</td>"
            f"<td>{remain}</td>"
            f"<td>{u.get('devices',1)}</td>"
            f"<td>{','.join(u.get('hwids',[])) or '-'}</td>"
            f"<td>{'نعم' if u.get('banned') else 'لا'}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan=5>لا يوجد</td></tr>")
    return "<table><tr><th>ID</th><th>المدة</th><th>الأجهزة</th><th>HWIDs</th><th>محظور؟</th></tr>" + "".join(rows) + "</table>"

def render_keys_table(db: dict, token: str | None = None) -> str:
    rows = []
    for k in db.get("keys", {}).values():
        mins = int(k.get("minutes",0))
        dur  = "غير محدود" if k.get("unlimited") else pretty_duration_from_secs(mins*60)
        rows.append(
            f"<tr><td>{k['code']}</td>"
            f"<td>{dur}</td>"
            f"<td>{k.get('devices',1)}</td>"
            f"<td>{'مرة واحدة' if k.get('single_use',True) else 'متكرر'}</td>"
            f"<td>{k.get('used_by') or '-'}</td></tr>"
        )
    if not rows:
        rows.append("<tr><td colspan=5>لا يوجد مفاتيح</td></tr>")
    table = "<table><tr><th>الكود</th><th>المدة</th><th>الأجهزة</th><th>الاستخدام</th><th>Used By</th></tr>" + "".join(rows) + "</table>"
    forms = (
        "<div style='margin-top:8px'>"
        "<form method='post' action='/admin/delete_key' style='display:inline-block'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        "حذف كود: <input name='code' placeholder='ABCD-1234' style='width:160px'> "
        "<button class='bad'>حذف</button>"
        "</form> "
        "<form method='post' action='/admin/edit_key' style='display:inline-block;margin-left:8px'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        "تعديل كود: <input name='code' placeholder='ABCD-1234' style='width:160px'> "
        "قيمة: <input name='amount' value='60' style='width:70px'> "
        "<select name='unit'><option value='m'>دقائق</option><option value='h'>ساعات</option><option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "أجهزة: <input name='devices' value='1' style='width:60px'> "
        "غير محدود؟ <input type='checkbox' name='unlimited'> "
        "مرّة واحدة؟ <input type='checkbox' name='single_use'> "
        "<button>تعديل</button>"
        "</form>"
        "</div>"
    )
    return table + forms

# ------------------------------ Admin UI ------------------------------
@app.get("/", response_class=HTMLResponse)
def admin_home(token: str | None = None):
    db = load_db()
    g  = db["globals"]
    topbar = (
        "<div class='topbar'>"
        "<div><h1 style='margin:0'>لوحة إدارة — MyAddon</h1></div>"
        f"<div class='badge'>أونلاين (تقريبي): <b>{g.get('online',0)}</b></div>"
        "</div>"
    )
    toggles = (
        "<div class='box'>"
        "<form method='post' action='/toggle'>"
        f"مدخل الإشراف (token): <input name='token' value='{token or ''}' style='width:160px'> "
        f"<button name='what' value='free'>{'إيقاف' if g.get('free_mode') else 'تشغيل'} الوضع المجاني</button> "
        f"<button name='what' value='lock'>{'فتح' if g.get('lockdown') else 'إغلاق'} عن الكل</button> "
        "</form>"
        "</div>"
    )
    activate_id = (
        "<div class='box'>"
        "<h2>تفعيل مباشر من ID</h2>"
        "<form method='post' action='/admin/activate_id'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        "ID: <input name='id' required style='width:140px'> "
        "قيمة: <input name='amount' value='30' style='width:70px'> "
        "وحدة: <select name='unit'>"
        "<option value='m'>دقائق</option><option value='h'>ساعات</option>"
        "<option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "أجهزة: <input name='devices' value='1' style='width:60px'> "
        "غير محدود؟ <input type='checkbox' name='unlimited'> "
        "<button>تفعيل/تعديل</button>"
        "</form>"
        "</div>"
    )
    keys_box = (
        "<div class='box'>"
        "<h2>مفاتيح</h2>"
        "<form method='post' action='/admin/create_key'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        "كود (اتركه فاضي للتوليد): <input name='code' placeholder='ABCD-1234-EFGH-5678' style='width:240px'> "
        "قيمة: <input name='amount' value='60' style='width:70px'> "
        "وحدة: <select name='unit'>"
        "<option value='m'>دقائق</option><option value='h'>ساعات</option>"
        "<option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "أجهزة: <input name='devices' value='1' style='width:60px'> "
        "غير محدود؟ <input type='checkbox' name='unlimited'> "
        "مرّة واحدة؟ <input type='checkbox' name='single_use' checked> "
        "<button>إضافة</button>"
        "</form>"
        "<div class='small'>المفاتيح الحالية:</div>"
        f"{render_keys_table(db, token)}"
        "</div>"
    )
    search_user = (
        "<div class='box'>"
        "<h2>بحث عن مستخدم</h2>"
        "<form method='get' action='/admin/user'>"
        "ID: <input name='id' style='width:160px'> "
        f"<input type='hidden' name='token' value='{token or ''}'>"
        "<button>بحث</button>"
        "</form>"
        "</div>"
    )
    lists_box = (
        "<div class='box'>"
        "<h2>القوائم</h2>"
        "<div class='small'>مشتركين:</div>"
        f"{render_users_table(db, only_active=True)}"
        "<hr>"
        "<div class='small'>محظورين:</div>"
        f"{render_users_table(db, only_banned=True)}"
        "</div>"
    )
    return html_shell("لوحة الإدارة", topbar + toggles + activate_id + keys_box + search_user + lists_box)

@app.post("/toggle")
def admin_toggle(what: str = Form(...), token: str = Form("")):
    db = load_db()
    require_admin(db, token, "admin")
    if what == "free":
        db["globals"]["free_mode"] = not db["globals"].get("free_mode", False)
    elif what == "lock":
        db["globals"]["lockdown"] = not db["globals"].get("lockdown", False)
    save_db(db)
    return RedirectResponse(url=f"/?token={token}", status_code=302)

@app.post("/admin/create_key")
def admin_create_key(
    token: str = Form(""),
    code: str = Form(""),
    amount: int = Form(60),
    unit: str = Form("m"),
    devices: int = Form(1),
    unlimited: str = Form(None),
    single_use: str = Form("on"),
):
    db = load_db()
    require_admin(db, token, "admin")
    minutes = 0 if unlimited else minutes_from_unit(amount, unit)
    if not code:
        parts = [secrets.token_hex(2).upper() for _ in range(4)]
        code = "-".join(parts)
    code = code.upper()
    if not KEY_RE.match(code):
        return PlainTextResponse("صيغة كود غير صحيحة", status_code=400)
    db.setdefault("keys", {})
    db["keys"][code] = {
        "code": code,
        "minutes": minutes,
        "devices": max(1,int(devices)),
        "unlimited": bool(unlimited),
        "single_use": (single_use is not None),
        "used_by": None
    }
    save_db(db)
    return RedirectResponse(url=f"/?token={token}", status_code=302)

@app.post("/admin/delete_key")
def admin_delete_key(token: str = Form(""), code: str = Form(...)):
    db = load_db()
    require_admin(db, token, "admin")
    code = code.upper()
    if code in db.get("keys", {}):
        del db["keys"][code]
        save_db(db)
        return RedirectResponse(url=f"/?token={token}", status_code=302)
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
    return RedirectResponse(url=f"/?token={token}", status_code=302)

@app.get("/admin/user", response_class=HTMLResponse)
def admin_get_user(id: str, token: str | None = None):
    db = load_db()
    u = db["users"].get(id)
    if not u:
        body = f"<div class='box'>لا يوجد مستخدم بهذا الـID: <b>{id}</b></div><a href='/?token={token or ''}'>رجوع</a>"
        return html_shell("المستخدم", body)
    remain = "غير محدود" if u.get("unlimited") else pretty_duration_from_secs(max(0, u.get("expires_at",0)-now_ts()))
    body = (
        "<div class='box'>"
        f"<h2>المستخدم: {id}</h2>"
        f"<div>المدة: <b>{remain}</b></div>"
        f"<div>الأجهزة: <b>{u.get('devices',1)}</b></div>"
        f"<div>HWIDs: <span class='small'>{','.join(u.get('hwids',[])) or '-'}</span></div>"
        f"<div>محظور؟ <b>{'نعم' if u.get('banned') else 'لا'}</b></div>"
        "<hr>"
        "<form method='post' action='/admin/adjust_time'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        f"<input type='hidden' name='id' value='{id}'>"
        "قيمة: <input name='amount' value='30' style='width:70px'> "
        "وحدة: <select name='unit'><option value='m'>دقائق</option><option value='h'>ساعات</option><option value='d'>أيام</option><option value='mo'>شهور</option></select> "
        "<button name='op' value='add'>زيادة</button> "
        "<button name='op' value='sub'>تنقيص</button>"
        "</form>"
        "<form method='post' action='/admin/set_devices' style='margin-top:8px'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        f"<input type='hidden' name='id' value='{id}'>"
        f"حد الأجهزة: <input name='devices' value='{u.get('devices',1)}' style='width:70px'> "
        "<button>تعديل</button>"
        "</form>"
        "<form method='post' action='/admin/set_unlimited' style='margin-top:8px'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        f"<input type='hidden' name='id' value='{id}'>"
        f"غير محدود؟ <input type='checkbox' name='unlimited' {'checked' if u.get('unlimited') else ''}> "
        "<button>تحديث</button>"
        "</form>"
        "<form method='post' action='/admin/ban' style='margin-top:8px;display:inline-block'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        f"<input type='hidden' name='id' value='{id}'>"
        "<button class='bad'>حظر</button>"
        "</form>"
        "<form method='post' action='/admin/unban' style='margin-top:8px;display:inline-block'>"
        f"<input type='hidden' name='token' value='{token or ''}'>"
        f"<input type='hidden' name='id' value='{id}'>"
        "<button class='ok'>فك الحظر</button>"
        "</form>"
        "<hr>"
        f"<a href='/?token={token or ''}'>رجوع</a>"
        "</div>"
    )
    return html_shell("المستخدم", body)

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
    return RedirectResponse(url=f"/admin/user?id={id}&token={token}", status_code=302)

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
        return RedirectResponse(url=f"/admin/user?id={id}&token={token}", status_code=302)
    mins = minutes_from_unit(amount, unit)
    cur = max(0, int(u.get("expires_at",0)))
    if op == "add":
        base = max(now_ts(), cur)
        u["expires_at"] = base + mins*60
    else:
        u["expires_at"] = max(0, cur - mins*60)
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}&token={token}", status_code=302)

@app.post("/admin/set_devices")
def admin_set_devices(token: str = Form(""), id: str = Form(...), devices: int = Form(...)):
    db = load_db()
    require_admin(db, token, "activator")
    u = ensure_user(db, id)
    u["devices"] = max(1, int(devices))
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}&token={token}", status_code=302)

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
    return RedirectResponse(url=f"/admin/user?id={id}&token={token}", status_code=302)

@app.post("/admin/ban")
def admin_ban(token: str = Form(""), id: str = Form(...)):
    db = load_db()
    require_admin(db, token, "admin")
    u = ensure_user(db, id)
    u["banned"] = True
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}&token={token}", status_code=302)

@app.post("/admin/unban")
def admin_unban(token: str = Form(""), id: str = Form(...)):
    db = load_db()
    require_admin(db, token, "admin")
    u = ensure_user(db, id)
    u["banned"] = False
    db["users"][id] = u
    save_db(db)
    return RedirectResponse(url=f"/admin/user?id={id}&token={token}", status_code=302)

# ------------------------------ Health ------------------------------
@app.get("/health")
def health():
    return {"ok": True}

# ------------------------------ Local dev runner ------------------------------
if __name__ == "__main__":
    import uvicorn, os
    uvicorn.run("app_single:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)
