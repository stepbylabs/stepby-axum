# -*- coding: utf-8 -*-
"""SSO/OIDC Provider 真实环境全链路验证脚本（v5 系列能力验收）。

用法：
    1. 启动依赖：docker compose up -d redis
    2. 配置（本地 .env）：
       SSO_ENABLED=true
       SSO_ISSUER=http://127.0.0.1:8080
       CONFIG_ENC_KEY=<>=32 字符随机串>
    3. 启动服务：cargo run
    4. 运行本脚本：python scripts/e2e_sso_oidc.py [--base http://127.0.0.1:8080]

覆盖链路（11 步，全部走真实 HTTP）：
    login → client 创建（RS256 keygen）→ authorize(302 code) →
    token 兑换（RS256 id_token + refresh_token 30d）→ id_token claims
    （acr/amr/tid/auth_time）→ JWKS 公钥独立 RSA 验签 → userinfo →
    refresh 轮换 → 旧 RT 重放拒绝(400) → revoke 即时失效(401) →
    /metrics SSO 事件序列

退出码：0 = 全部通过；非 0 = 任一步失败（详情见 stdout 与最后结果块）。
仅使用 Python 标准库，无第三方依赖。
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import re
import time
import urllib.parse

# PKCE 固定测试对（RFC 7636 附录 B 官方示例值，verifier/challenge 数学绑定）
PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
REDIRECT_URI = "http://127.0.0.1:9999/cb"


def b64u_dec(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def main():
    ap = argparse.ArgumentParser(description="SSO/OIDC 全链路真实验证")
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    args = ap.parse_args()
    host = urllib.parse.urlparse(args.base).netloc
    conn = http.client.HTTPConnection(host, timeout=10)
    out = []
    results = []  # (步骤名, 是否通过)

    def req(method, path, body=None, headers=None):
        h = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
            h.setdefault(
                "Content-Type",
                "application/json" if isinstance(body, dict) else "application/x-www-form-urlencoded",
            )
        conn.request(method, path, data, h)
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")

    def check(step, ok, detail=""):
        results.append((step, bool(ok)))
        out.append(f"[{'PASS' if ok else 'FAIL'}] {step} {detail}")

    # 1. login（captchaEnabled=false 场景；true 时需先取码）
    st, raw = req("POST", "/login", {"username": "admin", "password": "admin123"})
    token = json.loads(raw).get("token")
    check("1.login", bool(token), f"status={st}")
    auth = {"Authorization": f"Bearer {token}"}

    # 2. client 创建（grant_types 含 refresh_token；触发 RS256 keygen 大栈路径）
    st, raw = req("POST", "/system/oauth/client", {
        "clientName": f"e2e-{int(time.time())}",
        "redirectUris": [REDIRECT_URI],
        "scopes": ["openid", "profile", "email"],
        "consentRequired": "0", "enabled": "1",
        "grantTypes": ["authorization_code", "refresh_token"],
        "remark": "e2e_sso_oidc",
    }, auth)
    data = json.loads(raw)["data"]
    cid, csec = data["clientId"], data["clientSecret"]
    check("2.client_create", bool(cid) and len(csec) >= 32, f"cid={cid}")
    basic = base64.b64encode(f"{cid}:{csec}".encode()).decode()

    # 3. authorize（Admin-Token Cookie 会话）→ 302 code
    q = urllib.parse.urlencode({
        "client_id": cid, "redirect_uri": REDIRECT_URI,
        "response_type": "code", "scope": "openid profile email",
        "code_challenge": PKCE_CHALLENGE, "code_challenge_method": "S256",
        "state": "e2e",
    })
    conn.request("GET", f"/sso/authorize?{q}", None, {"Cookie": f"Admin-Token={token}"})
    r = conn.getresponse(); r.read()
    loc = r.getheader("Location") or ""
    m = re.search(r"[?&]code=([^&]+)", loc)
    code = urllib.parse.unquote(m.group(1)) if m else ""
    check("3.authorize_code", r.status == 302 and len(code) == 43, f"status={r.status}")

    # 4. token 兑换（Basic 认证）→ AT + RS256 id_token + RT
    tf = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT_URI, "code_verifier": PKCE_VERIFIER,
    })
    st, raw = req("POST", "/sso/token", tf, {"Authorization": f"Basic {basic}"})
    tok = json.loads(raw)
    check("4.token_exchange", st == 200 and bool(tok.get("id_token")) and bool(tok.get("refresh_token")),
          f"status={st} rtx={tok.get('refresh_expires_in')}")

    # 5. id_token claims（E5 认证强度 + N2 tid + auth_time）
    parts = tok["id_token"].split(".")
    idc = json.loads(b64u_dec(parts[1]))
    check("5.id_token_claims", idc.get("acr") in ("pwd", "mfa")
          and isinstance(idc.get("amr"), list) and "tid" in idc
          and idc.get("auth_time", 0) > 0,
          f"acr={idc.get('acr')} tid={idc.get('tid')}")

    # 6. JWKS 公钥独立 RSA 验签（PKCS#1 v1.5，不依赖后端任何实现）
    st, raw = req("GET", "/sso/jwks")
    jwk = next((k for k in json.loads(raw)["keys"] if k["kid"] == cid), None)
    n, e = b2i(b64u_dec(jwk["n"])), b2i(b64u_dec(jwk["e"]))
    sig = b64u_dec(parts[2])
    em = pow(b2i(sig), e, n).to_bytes((n.bit_length() + 7) // 8, "big")
    t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(
        f"{parts[0]}.{parts[1]}".encode()).digest()
    expected = b"\x00\x01" + b"\xff" * (len(em) - 3 - len(t)) + b"\x00" + t
    check("6.rs256_verify", hmac.compare_digest(em, expected))

    # 7. userinfo
    st, raw = req("GET", "/sso/userinfo", None, {"Authorization": f"Bearer {tok['access_token']}"})
    ui = json.loads(raw)
    check("7.userinfo", st == 200 and bool(ui.get("sub")), f"sub={ui.get('sub')}")

    # 8. refresh 轮换（新 AT/RT 均异于旧）
    rf = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]})
    st, raw = req("POST", "/sso/token", rf, {"Authorization": f"Basic {basic}"})
    tok2 = json.loads(raw)
    check("8.refresh_rotation", st == 200
          and tok2.get("access_token") != tok["access_token"]
          and tok2.get("refresh_token") != tok["refresh_token"])

    # 9. 旧 RT 重放 → 400 invalid_grant（轮换作废）
    st, _ = req("POST", "/sso/token", rf, {"Authorization": f"Basic {basic}"})
    check("9.old_rt_replay_rejected", st == 400, f"status={st}")

    # 10. revoke 即时失效（pre 200 → revoke 200 → post 401）
    st, _ = req("GET", "/sso/userinfo", None, {"Authorization": f"Bearer {tok2['access_token']}"})
    pre = st
    st, _ = req("POST", "/sso/revoke", urllib.parse.urlencode({"token": tok2["access_token"]}),
                {"Authorization": f"Basic {basic}"})
    rv = st
    st, _ = req("GET", "/sso/userinfo", None, {"Authorization": f"Bearer {tok2['access_token']}"})
    check("10.revoke_immediate", pre == 200 and rv == 200 and st == 401, f"pre={pre} rv={rv} post={st}")

    # 11. /metrics SSO 事件序列
    st, raw = req("GET", "/metrics")
    hit = ('yebot_sso_events_total{event="token_issued",outcome="ok"}' in raw
           and 'yebot_sso_events_total{event="token_revoked"' in raw
           and 'yebot_sso_events_total{event="authorize"' in raw)
    check("11.metrics_sso_events", hit)

    conn.close()

    # 汇总
    passed = sum(1 for _, ok in results if ok)
    out.append(f"\n=== RESULT: {passed}/{len(results)} passed ===")
    report = "\n".join(out)
    print(report)
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
