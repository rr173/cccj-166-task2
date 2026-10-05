"""安全通道：第二角色确认工作台 + 设备回执审计（8081）。

与业务通道完全隔离：独立端口、独立用户库（supervisor 可批准/拒绝，
safety 只读审计）、浏览器会话 Cookie（HttpOnly）。

确认动作强制"双证据"：
  1) 通过带外手段（电话/短信/硬令牌）收到的 6 位确认码；
  2) 页面展示创建时冻结的 SHA-256 摘要，第二角色核对后勾选/回填摘要。
"""
from __future__ import annotations

import html
import time

from .errors import Forbidden, Unauthorized
from .http_common import make_handler

ROUTES: list = []
COOKIE = "GWSEC_SESSION"


def route(path: str, method: str = "GET"):
    def deco(fn):
        ROUTES.append((path, method, fn))
        return fn
    return deco


def _check_login(h) -> dict:
    return h.require_session()


def _require_role(h, role: str) -> dict:
    s = _check_login(h)
    if role == "supervisor" and s["user"] != "supervisor":
        raise Forbidden("仅 supervisor 可执行确认/拒绝（职责分离）")
    return s


def _set_cookie(h, sid: str):
    h.send_header_add = None
    return f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/"


_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>{title} - 安全确认工作台</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,'Helvetica Neue',sans-serif;margin:0;background:#0f1420;color:#e6e9ef}}
header{{background:#172033;padding:12px 24px;border-bottom:1px solid #24304a;display:flex;gap:18px;align-items:center}}
header a{{color:#9db4d8;text-decoration:none;font-size:14px}} header b{{color:#fff}}
main{{padding:24px;max-width:1080px;margin:0 auto}}
.card{{background:#161d2e;border:1px solid #25314c;border-radius:10px;padding:18px;margin-bottom:16px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{border-bottom:1px solid #25314c;padding:7px 9px;text-align:left;vertical-align:top}}
th{{color:#8fa3c6;font-weight:600}} code,.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
.digest{{word-break:break-all;color:#7fd1b9;background:#10231f;padding:6px 8px;border-radius:6px;display:inline-block}}
.tag{{padding:1px 8px;border-radius:10px;font-size:12px}}
.PENDING{{background:#3a3210;color:#ffd76b}} .CONFIRMED{{background:#10304a;color:#7fc4ff}}
.EXECUTED{{background:#103a20;color:#7ff0ac}} .FAILED,.PARTIAL_FAILED{{background:#3d1620;color:#ff8ea3}}
.EXPIRED,.REVOKED,.REJECTED,.CLOSED{{background:#333845;color:#aab2c5}}
.DISPATCHED{{background:#10304a;color:#7fc4ff}} .DOUBT{{background:#4a2c10;color:#ffbd7f}}
.MISSED,.SKIPPED{{background:#2a2f3c;color:#9aa3b5}}
.OPEN{{background:#4a2c10;color:#ffbd7f}}
.RESOLVED{{background:#103a20;color:#7ff0ac}}
.REDELIVER_AFTER_REBOOT,.APPROVE_REDELIVER,.FACT_REPORTED{{background:#10304a;color:#7fc4ff}}
.FACT_RECOVERED,.FACT_RECOVERED_AFTER_MISSED{{background:#103a20;color:#7ff0ac}}
.CLOSED_MISSED{{background:#333845;color:#aab2c5}}
.MANUAL_NOTE{{background:#2c3142;color:#aab2c5}}
.LEDGER_CONFLICT{{background:#3d1620;color:#ff8ea3}}
input,textarea,select{{background:#0f1626;border:1px solid #31405f;color:#e6e9ef;border-radius:6px;padding:8px;margin:4px 0;width:320px}}
button{{background:#2f6df6;color:#fff;border:0;border-radius:6px;padding:9px 18px;cursor:pointer;margin-right:8px}}
button.danger{{background:#c0394f}} button.gray{{background:#3a4358}}
.flash{{background:#3d1620;color:#ffb3c0;padding:9px 14px;border-radius:8px;margin-bottom:14px}}
.ok{{background:#103a20;color:#7ff0ac}} .muted{{color:#8593ad;font-size:12px}}
</style></head><body><header>
<b>🛡 安全确认工作台</b>
<a href="/workbench">待确认/在途指令</a><a href="/tickets">事故对账工单</a>
<a href="/audit">审计事件链</a>
<a href="/receipts">回执审计</a><a href="/quarantine">账簿隔离区</a>
<a href="/devices">设备状态</a>
<span style="flex:1"></span><span class="muted">{user}</span>
<a href="/logout">登出</a></header><main>{flash}{body}</main></body></html>"""


def _page(h, title: str, body: str, flash: str = "", status: int = 200):
    s = h.ctx.sessions.get(h._session_cookie())
    user = s["user"] if s else "未登录"
    flash_html = f'<div class="flash {flash[1]}">{flash[0]}</div>' if flash else ""
    h.send_html(_PAGE.format(title=html.escape(title), body=body,
                             user=html.escape(user), flash=flash_html), status)


# ---------------- 登录 ----------------
@route("/login", "GET")
def login_form(h):
    if h.ctx.sessions.get(h._session_cookie()):
        return h.redirect("/workbench")
    body = """<div class="card"><h3>第二角色登录（独立安全通道）</h3>
    <form method="post" action="/login">
      <p><input name="username" placeholder="用户名 (supervisor / safety)" autocomplete="username"></p>
      <p><input name="password" type="password" placeholder="口令" autocomplete="current-password"></p>
      <button type="submit">登录</button>
    </form><p class="muted">supervisor=确认/拒绝；safety=只读审计</p></div>"""
    h.send_html(_PAGE.format(title="登录", body=body, user="未登录", flash=""))


@route("/login", "POST")
def login(h):
    from urllib.parse import parse_qs
    form = parse_qs(h._body().decode("utf-8"))
    u = (form.get("username") or [""])[0].strip()
    pw = (form.get("password") or [""])[0]
    import hmac as _hmac
    expect = h.ctx.cfg.sec_users.get(u)
    if expect is None or not _hmac.compare_digest(pw, expect):
        body = '<div class="flash">用户名或口令错误</div>' + \
            '<p><a href="/login">返回</a></p>'
        return h.send_html(_PAGE.format(title="登录失败", body=body, user="未登录", flash=""), 401)
    sid = h.ctx.sessions.create(u)
    h.send_response(302)
    h.send_header("Location", "/workbench")
    h.send_header("Set-Cookie", f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/")
    h.send_header("Content-Length", "0")
    h.end_headers()


@route("/logout", "GET")
def logout(h):
    sid = h._session_cookie()
    if sid:
        h.ctx.sessions.drop(sid)
    h.send_response(302)
    h.send_header("Location", "/login")
    h.send_header("Set-Cookie", f"{COOKIE}=; Max-Age=0; Path=/")
    h.send_header("Content-Length", "0")
    h.end_headers()


@route("/", "GET")
def root(h):
    h.redirect("/workbench" if h.ctx.sessions.get(h._session_cookie()) else "/login")


# ---------------- 工作台 ----------------
@route("/workbench", "GET")
def workbench(h):
    _check_login(h)
    cmds = h.ctx.svc.list_commands(limit=100)
    rows = []
    for c in cmds:
        tag = f'<span class="tag {c["status"]}">{c["status"]}</span>'
        rows.append(
            f'<tr><td class="mono"><a href="/commands/{c["command_id"]}" style="color:#9db4d8">'
            f'{c["command_id"]}</a></td><td>{html.escape(c["action"])}</td>'
            f'<td>{len(c["devices"])} 台</td><td>{tag}</td>'
            f'<td class="mono">{c["digest"][:16]}…</td>'
            f'<td class="muted">{_ts(c["created_at"])}</td></tr>')
    body = f"""<div class="card"><h3>指令列表</h3>
    <table><tr><th>指令</th><th>动作</th><th>设备</th><th>状态</th><th>冻结摘要</th><th>创建时间</th></tr>
    {''.join(rows) or '<tr><td colspan=6 class=muted>暂无指令</td></tr>'}</table></div>"""
    _page(h, "工作台", body)


@route("/commands/*", "GET")
def cmd_detail(h):
    s = _check_login(h)
    cid = h.raw_path.rsplit("/", 1)[-1]
    c = h.ctx.svc.get_command(cid)
    tgt_rows = []
    for t in c["targets"]:
        rec = ""
        if t["receipt"]:
            r = t["receipt"]
            rec = (f'回执: <b>{r["result"]}</b> <span class="muted">代号 {r["boot_code"]} '
                   f'#{r["seq"]} / 来源 {r["source"]}</span>')
        tk = h.ctx.svc.db.get_ticket_for_target(c["command_id"], t["device_id"])
        tkt_link = (f' <a href="/tickets/{tk["id"]}" style="color:#ffbd7f">事故工单 {tk["id"]}</a>'
                    if tk else "")
        tgt_rows.append(
            f'<tr><td class="mono">{t["device_id"]}</td>'
            f'<td><span class="tag {t["status"]}">{t["status"]}</span>{tkt_link}</td>'
            f'<td>{rec}</td></tr>')

    action_box = ""
    if c["status"] == "PENDING":
        if s["user"] == "supervisor":
            action_box = f"""
            <div class="card"><h3>⚠ 高风险指令确认</h3>
            <p class="muted">请通过独立带外通道获取 6 位确认码，并与送审来源核对以下冻结摘要：</p>
            <form method="post" action="/commands/{cid}/confirm">
              <p>带外确认码 <input name="confirm_code" inputmode="numeric" maxlength="6" required></p>
              <p>冻结摘要复核（完整复制后提交）<br>
              <span class="digest mono">{c["digest"]}</span><br>
              <input name="digest_ack" value="{c["digest"]}" class="mono" style="width:640px"></p>
              <button type="submit">✅ 确认下发</button>
            </form>
            <form method="post" action="/commands/{cid}/reject" style="margin-top:10px">
              <input name="reason" placeholder="拒绝原因" style="width:420px">
              <button class="danger" type="submit">⛔ 拒绝</button>
            </form></div>"""
        else:
            action_box = '<div class="card muted">只读账号：仅 supervisor 可确认/拒绝</div>'

    body = f"""<div class="card">
      <h3>{html.escape(c["action"])} <span class="tag {c["status"]}">{c["status"]}</span></h3>
      <table>
      <tr><th>指令 ID</th><td class="mono">{c["command_id"]}</td></tr>
      <tr><th>冻结设备集合</th><td class="mono">{html.escape(", ".join(c["devices"]))}</td></tr>
      <tr><th>冻结参数</th><td class="mono">{html.escape(str(c["params"]))}</td></tr>
      <tr><th>冻结摘要 SHA-256</th><td><span class="digest mono">{c["digest"]}</span></td></tr>
      <tr><th>有效窗口</th><td class="mono">{_ts(c["valid_from"])} → {_ts(c["valid_to"])}</td></tr>
      <tr><th>确认截止</th><td class="mono">{_ts(c["confirm_deadline"])}</td></tr>
      <tr><th>创建人 / 确认人</th><td>{html.escape(c["created_by"])} / {html.escape(str(c["confirmed_by"]))}</td></tr>
      </table></div>
      {action_box}
      <div class="card"><h3>设备执行情况</h3>
      <table><tr><th>设备</th><th>目标状态</th><th>执行事实</th></tr>{''.join(tgt_rows)}</table></div>"""
    _page(h, cid, body)


@route("/commands/*/confirm", "POST")
def web_confirm(h):
    from urllib.parse import parse_qs
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[2]
    form = parse_qs(h._body().decode("utf-8"))
    try:
        h.ctx.svc.confirm_command(
            actor=s["user"], command_id=cid,
            code=(form.get("confirm_code") or [""])[0],
            digest_ack=(form.get("digest_ack") or [""])[0])
        h.redirect(f"/commands/{cid}")
    except Exception as exc:
        _page(h, cid, f'<div class="flash">{html.escape(str(exc))}</div>'
                      f'<p><a href="/commands/{cid}">返回指令</a></p>',
              status=getattr(exc, "http_status", 400))


@route("/commands/*/reject", "POST")
def web_reject(h):
    from urllib.parse import parse_qs
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[2]
    form = parse_qs(h._body().decode("utf-8"))
    h.ctx.svc.reject_command(
        actor=s["user"], command_id=cid,
        reason=(form.get("reason") or [""])[0])
    h.redirect(f"/commands/{cid}")


# ---------------- 事故恢复对账工单 ----------------
@route("/tickets", "GET")
def tickets_page(h):
    _check_login(h)
    q = h.query()
    status = q.get("status", "OPEN")
    tickets = h.ctx.svc.list_recovery_tickets(status=status or None, limit=200)
    rows = []
    for t in tickets:
        conflict = (f'<span style="color:#ff8ea3">⚠ {html.escape(t["conflict_reason"])}</span>'
                    if t.get("conflict_reason") else "")
        rows.append(
            f'<tr><td class="mono"><a href="/tickets/{t["ticket_id"]}" style="color:#9db4d8">'
            f'{t["ticket_id"]}</a></td>'
            f'<td class="mono">{t["command_id"]}</td><td>{t["device_id"]}</td>'
            f'<td><span class="tag {t["status"]}">{t["status"]}</span></td>'
            f'<td>{html.escape(t["reason"])}</td>'
            f'<td><span class="tag {t.get("resolution") or ""}">{t.get("resolution") or "—"}</span></td>'
            f'<td>{conflict}</td>'
            f'<td class="muted">{_ts(t["updated_at"])}</td></tr>')
    tabs = (' | '.join(
        f'<a href="/tickets?status={s or ""}">{label}</a>'
        for s, label in (("OPEN", "挂起中"), ("RESOLVED", "已解决"), ("", "全部"))))
    body = f"""<div class="card"><h3>事故恢复对账工单（仅安全通道可见）<span class="muted" style="margin-left:12px">{tabs}</span></h3>
    <p class="muted">服务重启后，所有已送达现场但缺少终态回报的目标在此挂单；
    现场重新接入上传<b>带签名执行账簿</b>，系统校验代次、单调编号、指令指纹与账簿连续性后自动补记或重投。</p>
    <table><tr><th>工单</th><th>指令</th><th>设备</th><th>状态</th><th>挂起原因</th>
    <th>解决方式</th><th>冲突</th><th>最近活动</th></tr>
    {''.join(rows) or '<tr><td colspan=8 class=muted>暂无工单</td></tr>'}</table></div>"""
    _page(h, "事故对账工单", body)


@route("/tickets/*", "GET")
def ticket_detail(h):
    s = _check_login(h)
    tid = h.raw_path.rsplit("/", 1)[-1]
    t = h.ctx.svc.get_recovery_ticket(tid)
    ev = t["evidence"]
    is_supervisor = s["user"] == "supervisor"
    now = time.time()
    window_ok = ev.get("valid_to") and now < ev["valid_to"]

    evidence_rows = f"""
      <tr><th>指令 / 动作</th><td class="mono">{html.escape(t["command_id"])} / {html.escape(str(ev.get("action")))}</td></tr>
      <tr><th>现场设备</th><td>{html.escape(t["device_id"])}</td></tr>
      <tr><th>当前目标状态</th><td><span class="tag {ev.get("target_status") or ""}">{ev.get("target_status")}</span></td></tr>
      <tr><th>投递时间</th><td class="mono">{_ts(ev.get("dispatched_at"))}</td></tr>
      <tr><th>投递时启动代号</th><td class="mono">{html.escape(str(ev.get("dispatched_boot")))}</td></tr>
      <tr><th>原有效时限</th><td class="mono">{_ts(ev.get("valid_to"))} {"（仍有效）" if window_ok else "（已过期）"}</td></tr>
      <tr><th>冻结摘要</th><td><span class="digest mono">{html.escape(str(ev.get("digest")))}</span></td></tr>
      <tr><th>既有执行事实</th><td class="mono">{html.escape(str(ev.get("receipt"))) if ev.get("receipt") else "—"}</td></tr>"""

    conflict_box = ""
    if t.get("conflict_reason"):
        conflict_box = (f'<div class="flash">⚠ 最近冲突原因：<b>{html.escape(t["conflict_reason"])}</b>'
                        '（问题材料已隔离留痕，未改变任何状态）</div>')

    hist_rows = []
    for a in t.get("history", []):
        hist_rows.append(
            f'<tr><td>{a["id"]}</td><td class="mono">{_ts(a["ts"])}</td>'
            f'<td>{html.escape(a["actor"])}</td>'
            f'<td><span class="tag {a["action"]}">{a["action"]}</span></td>'
            f'<td class="mono" style="max-width:480px;word-break:break-all">'
            f'{html.escape(str(a["detail"]))}</td></tr>')

    q_rows = []
    for q in t.get("quarantine", []):
        q_rows.append(
            f'<tr><td>{q["id"]}</td><td><b style="color:#ff8ea3">{html.escape(q["reason"])}</b></td>'
            f'<td class="mono" style="word-break:break-all">{html.escape(str(q["raw"]))[:400]}</td>'
            f'<td class="muted">{_ts(q["received_at"])}</td></tr>')

    action_box = ""
    if t["status"] == "OPEN" and is_supervisor:
        redeliver_disabled = "" if window_ok else "disabled title='原时限已过期'"
        action_box = f"""
        <div class="card"><h3>人工处置（仅 supervisor）</h3>
        <p class="muted">硬边界：执行事实只能来自设备回执或校验通过的签名账簿；
        人工只能备注、批准重投（窗口须仍有效）或在过期后定 MISSED，
        <b>无法写入/覆盖 EXECUTED、FAILED</b>。</p>
        <form method="post" action="/tickets/{tid}/dispose">
          <input type="hidden" name="action" value="APPROVE_REDELIVER">
          <input name="note" placeholder="批准重投说明" style="width:420px">
          <button type="submit" {redeliver_disabled}>🔁 批准重新派发</button>
        </form>
        <form method="post" action="/tickets/{tid}/dispose" style="margin-top:8px">
          <input type="hidden" name="action" value="CLOSED_MISSED">
          <input name="note" placeholder="过期定 MISSED 说明" style="width:420px">
          <button class="gray" type="submit" {"disabled" if window_ok else ""}
            {"title='原时限仍有效'" if window_ok else ""}>⏳ 人工定 MISSED</button>
        </form>
        <form method="post" action="/tickets/{tid}/dispose" style="margin-top:8px">
          <input type="hidden" name="action" value="MANUAL_NOTE">
          <input name="note" placeholder="追加备注（不改状态）" style="width:420px">
          <button class="gray" type="submit">📝 添加备注</button>
        </form></div>"""
    elif not is_supervisor:
        action_box = '<div class="card muted">只读安全账号：仅 supervisor 可处置工单</div>'

    body = f"""<div class="card"><h3>工单 {t["ticket_id"]}
      <span class="tag {t["status"]}">{t["status"]}</span>
      <span class="tag {t.get("resolution") or ""}">{t.get("resolution") or ""}</span></h3>
      <table>{evidence_rows}</table></div>
      {conflict_box}{action_box}
      <div class="card"><h3>处置历史（append-only）</h3>
      <table><tr><th>#</th><th>时间</th><th>主体</th><th>动作</th><th>明细</th></tr>
      {''.join(hist_rows)}</table></div>
      <div class="card"><h3>关联隔离材料</h3>
      <table><tr><th>#</th><th>隔离原因</th><th>原始条目</th><th>时间</th></tr>
      {''.join(q_rows) or '<tr><td colspan=4 class=muted>无</td></tr>'}</table></div>"""
    _page(h, tid, body)


@route("/tickets/*/dispose", "POST")
def ticket_dispose(h):
    from urllib.parse import parse_qs
    s = _require_role(h, "supervisor")
    tid = h.raw_path.split("/")[2]
    form = parse_qs(h._body().decode("utf-8"))
    action = (form.get("action") or [""])[0]
    note = (form.get("note") or [""])[0]
    try:
        h.ctx.svc.dispose_ticket(actor=s["user"], ticket_id=tid,
                                 action=action, note=note)
        h.redirect(f"/tickets/{tid}")
    except Exception as exc:
        _page(h, tid, f'<div class="flash">{html.escape(str(exc))}</div>'
                      f'<p><a href="/tickets/{tid}">返回工单</a></p>',
              status=getattr(exc, "http_status", 400))


@route("/quarantine", "GET")
def quarantine_page(h):
    _check_login(h)
    items = h.ctx.svc.list_quarantine(limit=200)
    rows = [
        f'<tr><td>{q["id"]}</td><td>{q["device_id"]}</td>'
        f'<td><b style="color:#ff8ea3">{html.escape(q["reason"])}</b></td>'
        f'<td class="mono" style="word-break:break-all;max-width:560px">'
        f'{html.escape(str(q["raw"]))[:400]}</td>'
        f'<td class="muted">{_ts(q["received_at"])}</td></tr>'
        for q in items]
    body = """<div class="card"><h3>账簿隔离区（编号缺口 / 矛盾记录 / 过期时限 / 旧代次材料只隔离留痕）</h3>
    <table><tr><th>#</th><th>设备</th><th>隔离原因</th><th>原始材料</th><th>时间</th></tr>
    """ + "".join(rows) + """</table></div>"""
    _page(h, "账簿隔离区", body)


# ---------------- 审计 ----------------
@route("/audit", "GET")
def audit_page(h):
    _check_login(h)
    events = h.ctx.svc.audit_events(limit=100)
    chain = h.ctx.svc.verify_audit_chain()
    rows = []
    for e in reversed(events):
        rows.append(
            f'<tr><td>{e["id"]}</td><td class="mono">{_ts(e["ts"])}</td>'
            f'<td>{e["channel"]}</td><td>{html.escape(e["actor"])}</td>'
            f'<td><b>{e["action"]}</b></td>'
            f'<td class="mono" style="max-width:420px;overflow:hidden;text-overflow:ellipsis">'
            f'{html.escape(e["payload"][:200] if isinstance(e["payload"], str) else str(e["payload"])[:200])}</td>'
            f'<td class="mono" title="{e["hash"]}">{e["hash"][:10]}…</td></tr>')
    chain_badge = ('<span class="flash ok">✅ 哈希链校验通过：'
                   f'{chain["events"]} 个事件，链尾 {chain["head"][:16]}…</span>'
                   if chain["ok"] else
                   f'<span class="flash">❌ 哈希链断裂于事件 {chain["broken_at"]}：'
                   f'{chain["reason"]}</span>')
    body = f"""{chain_badge}<div class="card"><h3>审计事件（append-only 哈希链）</h3>
    <table><tr><th>#</th><th>时间</th><th>通道</th><th>主体</th><th>动作</th><th>内容</th><th>哈希</th></tr>
    {''.join(rows)}</table></div>
    <form method="post" action="/audit/verify"><button class="gray">重新校验哈希链</button></form>"""
    _page(h, "审计", body)


@route("/audit/verify", "POST")
def audit_verify(h):
    _check_login(h)
    h.redirect("/audit")


@route("/receipts", "GET")
def receipts_page(h):
    _check_login(h)
    accepted = h.ctx.svc.db.list_receipts()
    rejected = h.ctx.svc.rejected_receipts()
    a_rows = [
        f'<tr><td class="mono">{r["command_id"]}</td><td>{r["device_id"]}</td>'
        f'<td>{r["boot_code"]}</td><td>{r["seq"]}</td>'
        f'<td><span class="tag {r["result"]}">{r["result"]}</span></td>'
        f'<td>{r["source"]}</td><td class="muted">{html.escape(r["message"] or "")}</td></tr>'
        for r in accepted]
    r_rows = [
        f'<tr><td>{r["device_id"]}</td><td>{r.get("boot_code") or ""}</td>'
        f'<td>{r.get("seq")}</td><td><b>{r["reason"]}</b></td>'
        f'<td class="mono">{html.escape(str(r["raw"]))[:180]}</td></tr>'
        for r in rejected]
    body = f"""<div class="card"><h3>已接受回执（执行事实，不可变）</h3>
    <table><tr><th>指令</th><th>设备</th><th>启动代号</th><th>序号</th><th>结果</th><th>来源</th><th>说明</th></tr>
    {''.join(a_rows) or '<tr><td colspan=7 class=muted>暂无</td></tr>'}</table></div>
    <div class="card"><h3>被拒绝回执（旧代号 / 乱序 / 伪造，全部留痕）</h3>
    <table><tr><th>设备</th><th>启动代号</th><th>序号</th><th>拒绝原因</th><th>原始报文</th></tr>
    {''.join(r_rows) or '<tr><td colspan=5 class=muted>暂无</td></tr>'}</table></div>"""
    _page(h, "回执审计", body)


@route("/devices", "GET")
def devices_page(h):
    _check_login(h)
    rows = []
    for d in h.ctx.svc.list_devices():
        rows.append(
            f'<tr><td class="mono">{d["device_id"]}</td>'
            f'<td><span class="tag {"CONFIRMED" if d["online"] else "MISSED"}">'
            f'{"在线" if d["online"] else "离线"}</span></td>'
            f'<td class="mono">{d.get("current_boot") or "—"}</td>'
            f'<td>{d.get("ledger_head_seq")}</td>'
            f'<td class="muted">{_ts(d["last_seen"]) if d["last_seen"] else "—"}</td></tr>')
    body = """<div class="card"><h3>现场设备</h3>
    <table><tr><th>设备</th><th>状态</th><th>当前启动代号</th><th>已连续确认序号</th><th>最近心跳</th></tr>
    """ + "".join(rows) + "</table></div>"
    _page(h, "设备", body)


# ---------------- 供自动化/审计脚本调用的 JSON 接口（同样需要会话） ----------------
@route("/api/session", "POST")
def api_login(h):
    body = h.read_json()
    import hmac as _hmac
    u = body.get("username", "")
    pw = body.get("password", "")
    expect = h.ctx.cfg.sec_users.get(u)
    if expect is None or not _hmac.compare_digest(pw, expect):
        raise Unauthorized("安全通道凭据错误")
    sid = h.ctx.sessions.create(u)
    h.send_json({"ok": True, "user": u},
                extra_headers={"Set-Cookie":
                               f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/"})


@route("/api/commands", "GET")
def api_list(h):
    _check_login(h)
    q = h.query()
    h.send_json({"commands": h.ctx.svc.list_commands(status=q.get("status"))})


@route("/api/commands/*", "GET")
def api_detail(h):
    _check_login(h)
    cid = h.raw_path.rsplit("/", 1)[-1]
    h.send_json(h.ctx.svc.get_command(cid))


@route("/api/commands/*/confirm", "POST")
def api_confirm(h):
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.confirm_command(
        actor=s["user"], command_id=cid,
        code=body.get("confirm_code", ""), digest_ack=body.get("digest_ack", "")))


@route("/api/commands/*/reject", "POST")
def api_reject(h):
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.reject_command(
        actor=s["user"], command_id=cid, reason=body.get("reason", "")))


@route("/api/audit", "GET")
def api_audit(h):
    _check_login(h)
    q = h.query()
    h.send_json({"events": h.ctx.svc.audit_events(
        limit=int(q.get("limit", 200)),
        command_id=q.get("command_id"), device_id=q.get("device_id")),
        "chain": h.ctx.svc.verify_audit_chain()})


@route("/api/rejected", "GET")
def api_rejected(h):
    _check_login(h)
    h.send_json({"rejected": h.ctx.svc.rejected_receipts()})


@route("/api/tickets", "GET")
def api_tickets(h):
    _check_login(h)
    q = h.query()
    status = q.get("status") if q.get("status") else None
    h.send_json({"tickets": h.ctx.svc.list_recovery_tickets(status=status)})


@route("/api/tickets/*", "GET")
def api_ticket_detail(h):
    _check_login(h)
    tid = h.raw_path.split("/")[3]
    h.send_json(h.ctx.svc.get_recovery_ticket(tid))


@route("/api/tickets/*/dispose", "POST")
def api_ticket_dispose(h):
    s = _require_role(h, "supervisor")
    tid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.dispose_ticket(
        actor=s["user"], ticket_id=tid, action=body.get("action", ""),
        note=body.get("note", "")))


@route("/api/quarantine", "GET")
def api_quarantine(h):
    _check_login(h)
    q = h.query()
    h.send_json({"quarantine": h.ctx.svc.list_quarantine(
        device_id=q.get("device"))})


@route("/healthz", "GET")
def health(h):
    h.send_json({"channel": "security", "ok": True})


def _ts(v) -> str:
    import datetime
    if not v:
        return "—"
    return datetime.datetime.fromtimestamp(v).strftime("%m-%d %H:%M:%S")


def build_handler(ctx):
    return make_handler(ctx, ROUTES)
