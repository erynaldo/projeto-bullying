import io, math, os, re
from datetime import datetime
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, jsonify,
    send_file, flash
)
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import CSRFProtect
# from werkzeug.security import check_password_hash
from werkzeug.security import check_password_hash, generate_password_hash
# import mysql.connector
import psycopg2
from psycopg2.extras import DictCursor
import pandas as pd


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "chave_super_segura")

# CSRF
csrf = CSRFProtect(app)

# Login
login_manager = LoginManager(app)
login_manager.login_view = "login"

# login_manager_aluno = LoginManager(app)
# login_manager_aluno.login_view = "login-aluno"

# Esse para acesso local
# DB_CONFIG = dict(
#     host=os.getenv("DB_HOST"),
#     user=os.getenv("DB_USER"),
#     password=os.getenv("DB_PASS"),
#     database=os.getenv("DB_NAME"),
#     port=int(os.getenv("DB_PORT"))  # Porta padrão do PostgreSQL
# )

# Esse para acesso site Neon console
DB_CONFIG = dict(
    host=os.getenv("PGHOST"),
    user=os.getenv("PGUSER"),
    password=os.getenv("PGPASSWORD"),
    database=os.getenv("PGDATABASE"),
    sslmode=os.getenv("PGSSLMODE"),
    channel_binding=os.getenv("PGCHANNELBINDING")
)

def get_conn():
    return psycopg2.connect(**DB_CONFIG)

conn = psycopg2.connect(**DB_CONFIG)


# def get_conn():
#     return mysql.connector.connect(**DB_CONFIG)

# --------- Utils ----------
CPF_RE = re.compile(r"^\d{11}$")
def only_digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")

def valida_cpf(cpf: str) -> bool:
    cpf = only_digits(cpf)
    if not CPF_RE.match(cpf): return False
    if cpf == cpf[0]*11: return False
    def dv_calc(slice_, peso_ini):
        soma, p = 0, peso_ini
        for ch in slice_:
            soma += int(ch)*p; p -= 1
        resto = (soma*10) % 11
        return 0 if resto == 10 else resto
    d1 = dv_calc(cpf[:9], 10)
    if d1 != int(cpf[9]): return False
    d2 = dv_calc(cpf[:10], 11)
    return d2 == int(cpf[10])

# --------- User model p/ Flask-Login ----------
class User(UserMixin):
    def __init__(self, id_, nome, usuario):
        self.id = id_
        self.nome = nome  # pode ser usado para exibir o nome no admin
        self.usuario = usuario  # CPF
    
    # def __init__(self, id_, nome_aluno, matricula_ra, gmail_aluno, usuario_github):
    #     self.id = id_
    #     self.nome_aluno = nome_aluno
    #     self.matricula_ra = matricula_ra
    #     self.gmail_aluno = gmail_aluno
    #     self.usuario_github = usuario_github


@login_manager.user_loader
def load_user(user_id):
    conn = get_conn()
    # from psycopg2.extras import DictCursor
    cur = conn.cursor(cursor_factory=DictCursor)
    # cur = conn.cursor()
    
    cur.execute("SELECT id, nome, usuario FROM admin WHERE id=%s", (user_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row: return None
    return User(row["id"], row["nome"], row["usuario"])


# --------- Rotas Públicas ----------
@app.route("/", methods=["GET","POST"])
def index():
    if request.method == "POST":
        tipo = request.form.get("tipo")
        descricao = (request.form.get("descricao") or "").strip()
        agressor = (request.form.get("agressor") or "").strip() or None

        if tipo not in ("bullying","outras") or not descricao:
            flash("Preencha corretamente os campos obrigatórios.", "erro")
            return render_template("index.html")

        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO denuncias (tipo, descricao, agressor) VALUES (%s,%s,%s)",
            (tipo, descricao, agressor)
        )
        conn.commit()
        cur.close(); conn.close()
        return render_template("index.html", sucesso=True)

    return render_template("index.html")

# --------- Login / Logout ----------
# @app.route("/login", methods=["GET","POST"])
# def login():
#     if request.method == "POST":
#         usuario_raw = request.form.get("usuario")  # CPF
#         senha = request.form.get("senha") or ""
#         cpf = only_digits(usuario_raw)

#         if not valida_cpf(cpf):
#             return render_template("login.html", erro="CPF inválido.")

#         conn = get_conn()
#         cur = conn.cursor(dictionary=True)
#         cur.execute("SELECT * FROM admin WHERE usuario=%s", (cpf,))
#         adm = cur.fetchone()
#         cur.close(); conn.close()

#         if not adm or not check_password_hash(adm["senha"], senha):
#             return render_template("login.html", erro="CPF ou senha inválidos.")

#         login_user(User(adm["id"], adm["usuario"]))
#         return redirect(url_for("admin"))

#     return render_template("login.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        usuario_raw = request.form.get("usuario")  # CPF vindo do form
        senha = request.form.get("senha") or ""
        if not usuario_raw:
            return render_template("login.html", erro="Informe CPF e senha.")

        cpf = only_digits(usuario_raw)

        # Valida CPF (mesma função que você já tem)
        if not valida_cpf(cpf):
            return render_template("login.html", erro="CPF inválido.")

        # from psycopg2.extras import DictCursor

        conn = get_conn()       
        cur = conn.cursor(cursor_factory=DictCursor)
   
        cur.execute("SELECT * FROM admin WHERE usuario=%s", (cpf,))
        adm = cur.fetchone()

        if not adm:
            cur.close(); conn.close()
            return render_template("login.html", erro="CPF ou senha inválidos.")

        stored = adm.get("senha") or ""
        valid = False

        # 1) tenta validar como hash (forma correta)
        try:
            if check_password_hash(stored, senha):
                valid = True
        except Exception:
            # check_password_hash pode lançar se o formato do 'stored' não for esperado:
            valid = False

        # 2) fallback: se a senha no DB estiver em texto simples, aceite e migre para hash
        if not valid:
            if stored == senha:
                valid = True
                try:
                    new_hash = generate_password_hash(senha)

                    conn = get_conn()
                    # from psycopg2.extras import DictCursor
                    cur = conn.cursor(cursor_factory=DictCursor)

                    cur = conn.cursor()
                    cur.execute("UPDATE admin SET senha=%s WHERE id=%s", (new_hash, adm["id"]))
                    conn.commit()
                    cur.close()
                except Exception:
                    # se falhar ao atualizar, não interrompe o login -- apenas logue se quiser
                    pass

        cur.close(); conn.close()

        if not valid:
            return render_template("login.html", erro="CPF ou senha inválidos.")

        # sucesso: faz login com Flask-Login e redireciona ao admin
        login_user(User(adm["id"], adm["nome"], adm["usuario"]))
        return redirect(url_for("admin"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# --------- Admin Helpers ----------
def build_filters(args):
    where = "WHERE 1=1"
    params = []
    tipo = args.get("tipo","").strip()
    data = args.get("data","").strip()
    data_inicio = args.get("data_inicio","").strip()
    data_fim = args.get("data_fim","").strip()
    filtro_status = args.get("status","").strip()

    if tipo in ("bullying","outras"):
        where += " AND tipo=%s"; params.append(tipo)
    if data:
        where += " AND DATE(data_envio)=%s"; params.append(data)
    if data_inicio and data_fim:
        where += " AND DATE(data_envio) BETWEEN %s AND %s"; params.extend([data_inicio, data_fim])
    if filtro_status in ("em análise","resolvida","falsa","grave","gravíssima"):
        where += " AND status=%s"; params.append(filtro_status)

    return where, params, tipo, data, data_inicio, data_fim, filtro_status

def get_kpis(cur, where, params):
    cur.execute(f"SELECT COUNT(*) c FROM denuncias {where} AND tipo='bullying'", params)
    bullying = cur.fetchone()["c"]
    cur.execute(f"SELECT COUNT(*) c FROM denuncias {where} AND tipo='outras'", params)
    outras = cur.fetchone()["c"]
    return bullying, outras, bullying+outras


# --------- Admin ----------
@app.route("/admin")
@login_required
def admin():
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 10)), 5), 50)
    offset = (page - 1) * per_page

    where, params, tipo, data, data_inicio, data_fim, filtro_status = build_filters(request.args)

    conn = get_conn()
    cur = conn.cursor(cursor_factory=DictCursor)

    # Total e KPIs
    cur.execute(f"SELECT COUNT(*) total FROM denuncias {where}", params)
    total = cur.fetchone()["total"]
    total_pages = max(math.ceil(total / per_page), 1)
    k_b, k_o, k_t = get_kpis(cur, where, params)


    # Página de dados
    cur.execute(
        f"""SELECT id, tipo, descricao, agressor, data_envio, status
            FROM denuncias {where}
            ORDER BY data_envio DESC, id DESC
            LIMIT %s OFFSET %s""",
        (*params, per_page, offset)
    )
    denuncias = cur.fetchall()

    cur.close(); conn.close()

    # return render_template(
    #     "admin.html",
    #     denuncias=denuncias,
    #     kpi_bullying=k_b,
    #     kpi_outras=k_o,
    #     kpi_total=k_t,
    #     page=page, per_page=per_page, total=total, total_pages=total_pages,
    #     filtro_tipo=tipo, filtro_data=data, filtro_data_inicio=data_inicio, filtro_data_fim=data_fim, filtro_status=filtro_status
    # )

    # ...existing code...
    status_counts = get_status_counts(cur, where, params)
# ...existing code...
    return render_template(
        "admin.html",
        denuncias=denuncias,
        kpi_bullying=k_b,
        kpi_outras=k_o,
        kpi_total=k_t,
        page=page, per_page=per_page, total=total, total_pages=total_pages,
        filtro_tipo=tipo, filtro_data=data, filtro_data_inicio=data_inicio, filtro_data_fim=data_fim, filtro_status=filtro_status,
        status_counts=status_counts  # <-- Adicione esta linha
    )
# ...existing code...

# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

def get_status_counts(cur, where, params):
    conn = get_conn()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute(
        f"SELECT status, COUNT(*) as total FROM denuncias {where} GROUP BY status",
        params
    )
    rows = cur.fetchall()
    # Garante todos os status possíveis, mesmo que estejam zerados
    status_list = ["em análise", "resolvida", "falsa", "grave", "gravíssima"]
    counts = {status: 0 for status in status_list}
    for row in rows:
        counts[row["status"]] = row["total"]
    return counts


# --------- Exportar Excel ----------
@app.route("/admin/exportar")
@login_required
def admin_exportar():
    where, params, *_ = build_filters(request.args)
    conn = get_conn()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute(
        f"SELECT id, tipo, descricao, agressor, data_envio, status FROM denuncias {where} ORDER BY data_envio DESC, id DESC",
        params
    )
    rows = cur.fetchall()
    cur.close(); conn.close()

    df = pd.DataFrame(rows)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Denuncias")
    output.seek(0)
    return send_file(output, as_attachment=True,
        download_name="denuncias.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")



# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

@app.route("/api/status_counts")
@login_required
def api_status_counts():
    where, params, *_ = build_filters(request.args)
    conn = get_conn()
    cur = conn.cursor(cursor_factory=DictCursor)
    counts = get_status_counts(cur, where, params)
    cur.close(); conn.close()
    return jsonify(counts)



# =========================================================================================


# class UserAluno(UserMixin):
#     def __init__(self, id_, nome_aluno, matricula_ra, gmail_aluno, usuario_github):
#         self.id = id_
#         self.nome_aluno = nome_aluno
#         self.matricula_ra = matricula_ra
#         self.gmail_aluno = gmail_aluno
#         self.usuario_github = usuario_github
# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx AQUI DEVO MUDAR xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# @login_manager_aluno.user_loader
# def load_user(user_id):
#     conn = get_conn()
#     cur = conn.cursor(cursor_factory=DictCursor)

#     cur.execute("SELECT id, nome_aluno, matricula_ra, gmail_aluno, usuario_github FROM aluno WHERE id=%s", (user_id,))
#     row = cur.fetchone()
#     cur.close(); conn.close()
#     if not row: return None
#     return User(row["id"], row["nome_aluno"], row["matricula_ra"], row["gmail_aluno"], row["usuario_github"])



@app.route("/login-aluno", methods=["GET","POST"])
def login_aluno():
    if request.method == "POST":
        matricula_ra = request.form.get("matricula_ra") or ""
        if not matricula_ra:
            return render_template("login-aluno.html", erro="RA está incorreto")

        conn = get_conn()       
        cur = conn.cursor(cursor_factory=DictCursor)

        cur.execute("SELECT * FROM aluno WHERE matricula_ra=%s", (matricula_ra,))
        adm = cur.fetchone()

        if not adm:
            cur.close(); conn.close()
            # aqui diz que o RA está invalido ou não existe
            return render_template("login-aluno.html", erro="RA inválido")
  
        
        # sucesso: faz login com Flask-Login e redireciona ao admin
        login_user(User(adm["id"], adm["nome_aluno"], adm["matricula_ra"]))
        return redirect(url_for("aluno"))

    return render_template("login-aluno.html")


@app.route("/logout_aluno")
@login_required
def logout_aluno():
    logout_user()
    return redirect(url_for("login_aluno"))


# =========================================================================================



# --------- Aluno ----------xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

@app.route("/aluno")
@login_required
def aluno():
   
    conn = get_conn()
    cur = conn.cursor(cursor_factory=DictCursor)

    # Página de dados
    cur.execute(
        f"""SELECT id, nome_aluno, matricula_ra, gmail_aluno, usuario_github
            FROM aluno"""
    )
    dados_aluno = cur.fetchall()

    cur.close(); conn.close()

# ...existing code...
    return render_template(
        "aluno.html",
        dados_aluno=dados_aluno  # <-- Adicione esta linha
    )
# ...fim aluno code...xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx




# --------- API: alterar status (AJAX) ----------
@app.route("/api/denuncias/<int:denuncia_id>/status", methods=["POST"])
@login_required
@csrf.exempt   # vamos validar CSRF manualmente pelo header para AJAX
def api_alterar_status(denuncia_id):
    # valida CSRF (header X-CSRFToken)
    token = request.headers.get("X-CSRFToken")
    from flask_wtf.csrf import validate_csrf, CSRFError
    try:
        validate_csrf(token)
    except Exception:
        return jsonify({"ok": False, "error": "CSRF inválido"}), 400

    novo_status = (request.json or {}).get("status")
    if novo_status not in ("em análise","resolvida","falsa","grave","gravíssima"):
        return jsonify({"ok": False, "error": "status inválido"}), 400

    conn = get_conn()
    cur = conn.cursor(cursor_factory=DictCursor)

    # pega status atual p/ log
    cur.execute("SELECT status FROM denuncias WHERE id=%s", (denuncia_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"ok": False, "error": "denúncia não encontrada"}), 404
    status_atual = row["status"]

    # atualiza
    cur2 = conn.cursor()
    cur2.execute("UPDATE denuncias SET status=%s WHERE id=%s", (novo_status, denuncia_id))
    conn.commit()
    cur2.close()

    # log
    cur3 = conn.cursor()
    cur3.execute(
        "INSERT INTO audit_log (denuncia_id, usuario, de_status, para_status) VALUES (%s,%s,%s,%s)",
        (denuncia_id, current_user.usuario, status_atual, novo_status)
    )
    conn.commit()
    cur3.close(); cur.close(); conn.close()

    return jsonify({"ok": True})
    
if __name__ == "__main__":
    app.run(debug=True)
