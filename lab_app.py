"""Laboratório para a auditoria OWASP: app INTENCIONALMENTE VULNERÁVEL e sua versão corrigida.

Uso:
    python lab_app.py vulneravel   ->  http://127.0.0.1:5000
    python lab_app.py seguro       ->  http://127.0.0.1:5001

Só para estudo, em ambiente local. NUNCA exponha este app na internet.
"""
import sqlite3
import sys
import time

from flask import Flask, request
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

MAX_FAILS, BLOCK_SECONDS = 5, 60


def create_app(mode):
    secure = mode == "seguro"
    app = Flask(__name__)
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    seed = [("admin", "Adm!nSecreta#2024", "administrador"), ("maria", "maria123", "cliente")]
    for user, pwd, role in seed:
        stored = generate_password_hash(pwd) if secure else pwd  # vulnerável: senha em texto puro
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (user, stored, role))
    db.commit()
    fails = {}  # ip -> (falhas, bloqueado_até)

    def page(body):
        cor = "#0a7d2c" if secure else "#b00020"
        rotulo = "SEGURO (corrigido)" if secure else "VULNERÁVEL"
        return (
            "<body style='font-family:sans-serif;max-width:640px;margin:30px auto'>"
            f"<div style='background:{cor};color:#fff;padding:8px'>MODO: {rotulo}</div>"
            f"{body}<hr><a href='/'>Início</a></body>"
        )

    @app.route("/")
    def home():
        return page(
            "<h2>Loja de teste</h2>"
            "<h3>Login</h3>"
            "<form method='post' action='/login'>"
            "Usuário: <input name='username'><br><br>"
            "Senha: <input name='password' type='password'><br><br>"
            "<button>Entrar</button></form>"
            "<h3>Buscar produtos</h3>"
            "<form method='get' action='/search'><input name='q'> <button>Buscar</button></form>"
        )

    @app.route("/login", methods=["POST"])
    def login():
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        ip = request.remote_addr

        if secure:
            n, ate = fails.get(ip, (0, 0))
            if time.time() >= ate:
                n = 0
            if n >= MAX_FAILS:
                return page("<h3>Muitas tentativas. Tente novamente em 1 minuto.</h3>"), 429
            # CORREÇÃO: consulta parametrizada + comparação de hash
            row = db.execute("SELECT username, password, role FROM users WHERE username = ?", (u,)).fetchone()
            ok = row is not None and check_password_hash(row[1], p)
            if not ok:
                fails[ip] = (n + 1, time.time() + BLOCK_SECONDS)
            else:
                fails.pop(ip, None)
            if ok:
                return page(f"<h3>Login OK! Bem-vindo, {escape(row[0])} ({escape(row[2])})</h3>")
            return page("<h3>Usuário ou senha incorretos.</h3>"), 401

        # VULNERÁVEL: concatenação de texto na consulta SQL (SQL Injection) e sem limite de tentativas
        sql = f"SELECT username, password, role FROM users WHERE username = '{u}' AND password = '{p}'"
        info = f"<p><small>Consulta executada:<br><code>{escape(sql)}</code></small></p>"
        try:
            row = db.execute(sql).fetchone()
        except sqlite3.Error as e:
            return page(f"<h3>Erro SQL: {escape(e)}</h3>{info}"), 500
        if row:
            return page(f"<h3>Login OK! Bem-vindo, {escape(row[0])} ({escape(row[2])})</h3>{info}")
        return page(f"<h3>Usuário ou senha incorretos.</h3>{info}"), 401

    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # VULNERÁVEL: devolve a entrada sem tratamento (XSS refletido). CORREÇÃO: escape + CSP
        shown = escape(q) if secure else q
        resp = app.make_response(page(f"<h3>Resultados para: {shown}</h3><p>Nenhum produto encontrado.</p>"))
        if secure:
            resp.headers["Content-Security-Policy"] = "script-src 'self'"
        return resp

    return app


if __name__ == "__main__":
    modo = sys.argv[1] if len(sys.argv) > 1 else "vulneravel"
    if modo not in ("vulneravel", "seguro"):
        sys.exit("Use: python lab_app.py vulneravel   ou   python lab_app.py seguro")
    create_app(modo).run(host="127.0.0.1", port=5001 if modo == "seguro" else 5000, debug=False)
