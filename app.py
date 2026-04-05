"""
app.py - CISP Governance — Versão Final Melhorada
- Login com imagem cisp.jpg
- Roles: admin, gestor, analista, auditor
- SQLAlchemy (Postgres ou SQLite)
- Audit logs com old_values/new_values JSON + access_logs
- Dashboard com alertas de prazo, matriz colorida, KPIs
- Sidebar de navegação
- Filtros/busca em todas as tabelas
- Detecção Automática com promoção de riscos ao BD
- Admin: tabs Usuários / Logs Acesso / Logs Ações / Estatísticas
"""

import os
import json
import base64
from datetime import datetime, date, timedelta
from functools import wraps
import random

import streamlit as st
import pandas as pd
import altair as alt
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, Text,
    Date, DateTime, Boolean, ForeignKey, select, func, inspect, text
)
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv
import bcrypt

load_dotenv()

# --------------------------
# Config DB
# --------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    engine = create_engine(DATABASE_URL, echo=False, future=True)
else:
    engine = create_engine("sqlite:///cisp_gov.db", echo=False, future=True)

metadata = MetaData()

# --------------------------
# Tables
# --------------------------
users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True, nullable=False),
    Column("password_hash", String, nullable=False),
    Column("role", String, nullable=False),
    Column("full_name", String, nullable=True),
    Column("is_active", Boolean, default=True),
    Column("created_at", DateTime, default=func.now()),
    Column("last_login", DateTime, nullable=True),
)

policies = Table(
    "policies", metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),
    Column("version", String, nullable=False),
    Column("owner", String, nullable=False),
    Column("classification", String, nullable=False),
    Column("scope", Text),
    Column("status", String, nullable=False),
    Column("effective_date", Date),
    Column("next_review_date", Date),
    Column("body", Text),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now()),
)

assets = Table(
    "assets", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("type", String, nullable=False),
    Column("owner", String, nullable=False),
    Column("criticality", String, nullable=False),
)

risks = Table(
    "risks", metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),
    Column("description", Text),
    Column("asset_id", Integer, ForeignKey("assets.id"), nullable=True),
    Column("category", String),
    Column("likelihood", Integer),
    Column("impact", Integer),
    Column("inherent", Integer),
    Column("controls", Text),
    Column("residual", Integer),
    Column("owner", String),
    Column("status", String),
    Column("review_date", Date),
    Column("created_at", DateTime, default=func.now()),
)

incidents = Table(
    "incidents", metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),
    Column("severity", String),
    Column("category", String),
    Column("detected_at", DateTime),
    Column("contained_at", DateTime, nullable=True),
    Column("eradicated_at", DateTime, nullable=True),
    Column("recovered_at", DateTime, nullable=True),
    Column("status", String),
    Column("description", Text),
    Column("root_cause", Text),
    Column("lessons_learned", Text),
    Column("notification_required", Boolean, default=False),
    Column("notified_at", DateTime, nullable=True),
    Column("created_at", DateTime, default=func.now()),
)

dsar = Table(
    "dsar", metadata,
    Column("id", Integer, primary_key=True),
    Column("requester", String),
    Column("type", String),
    Column("received_date", Date),
    Column("due_date", Date),
    Column("status", String),
    Column("notes", Text),
)

audits = Table(
    "audits", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String),
    Column("audit_date", Date),
    Column("scope", Text),
    Column("findings", Text),
    Column("status", String),
)

trainings = Table(
    "trainings", metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String),
    Column("audience", String),
    Column("start_date", Date),
    Column("end_date", Date),
    Column("status", String),
)

audit_logs = Table(
    "audit_logs", metadata,
    Column("id", Integer, primary_key=True),
    Column("actor", String),
    Column("role", String),
    Column("action", String),
    Column("target_table", String),
    Column("target_id", Integer, nullable=True),
    Column("old_values", Text, nullable=True),
    Column("new_values", Text, nullable=True),
    Column("details", Text, nullable=True),
    Column("ip_address", String, nullable=True),
    Column("user_agent", String, nullable=True),
    Column("created_at", DateTime, default=func.now()),
)

access_logs = Table(
    "access_logs", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String),
    Column("role", String),
    Column("action", String),
    Column("ip_address", String, nullable=True),
    Column("user_agent", String, nullable=True),
    Column("details", Text, nullable=True),
    Column("created_at", DateTime, default=func.now()),
)

# --------------------------
# Bootstrap
# --------------------------
def bootstrap():
    try:
        metadata.create_all(engine)
    except OperationalError as e:
        st.error(f"Erro criando tabelas: {e}")

    # Migrações para bases antigas
    inspector = inspect(engine)
    if "policies" in inspector.get_table_names():
        existing = [c["name"] for c in inspector.get_columns("policies")]
        if "updated_at" not in existing:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE policies ADD COLUMN updated_at DATETIME"))
                conn.commit()
    if "users" in inspector.get_table_names():
        existing = [c["name"] for c in inspector.get_columns("users")]
        for col, ddl in [("is_active", "BOOLEAN DEFAULT 1"),
                         ("created_at", "DATETIME"),
                         ("last_login", "DATETIME")]:
            if col not in existing:
                with engine.connect() as conn:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {ddl}"))
                    conn.commit()

    with engine.connect() as conn:
        r = conn.execute(select(users.c.id).where(users.c.username == "admin")).first()
        if not r:
            pw = hash_password("admin123")
            conn.execute(users.insert().values(
                username="admin", password_hash=pw, role="admin",
                full_name="Administrador", is_active=True
            ))
            conn.commit()

# --------------------------
# Security helpers
# --------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def get_client_info():
    import socket
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "127.0.0.1"
    return ip, "Streamlit-App/1.0"

def log_access(username, role, action, details=None):
    ip, ua = get_client_info()
    with engine.connect() as conn:
        conn.execute(access_logs.insert().values(
            username=username, role=role, action=action,
            ip_address=ip, user_agent=ua,
            details=details, created_at=datetime.utcnow()
        ))
        conn.commit()

def log_action(actor, role, action, target_table=None, target_id=None,
               old_values=None, new_values=None, details=None):
    ip, ua = get_client_info()
    old_json = json.dumps(old_values, ensure_ascii=False, default=str) if old_values else None
    new_json = json.dumps(new_values, ensure_ascii=False, default=str) if new_values else None
    with engine.connect() as conn:
        conn.execute(audit_logs.insert().values(
            actor=actor, role=role, action=action,
            target_table=target_table, target_id=target_id,
            old_values=old_json, new_values=new_json,
            details=details, ip_address=ip, user_agent=ua,
            created_at=datetime.utcnow()
        ))
        conn.commit()

def require_roles(allowed):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = st.session_state.get("user")
            if not user:
                st.error("Acesso negado: autentique-se.")
                return
            if user["role"] == "admin" or user["role"] in allowed:
                return fn(*args, **kwargs)
            st.warning("⛔ Permissão negada para o seu perfil.")
        return wrapper
    return deco

# --------------------------
# DB helpers
# --------------------------
def fetch_df(table):
    with engine.connect() as conn:
        return pd.read_sql(select(table), conn)

def get_row(table, row_id):
    with engine.connect() as conn:
        row = conn.execute(select(table).where(table.c.id == row_id)).mappings().first()
    return dict(row) if row else None

def update_row(table, row_id, values):
    with engine.connect() as conn:
        conn.execute(table.update().where(table.c.id == row_id).values(**values))
        conn.commit()

def delete_row(table, row_id):
    with engine.connect() as conn:
        conn.execute(table.delete().where(table.c.id == row_id))
        conn.commit()

def days_overdue(d):
    if not d:
        return None
    if isinstance(d, datetime):
        d = d.date()
    return (date.today() - d).days

# --------------------------
# Imagem CISP
# --------------------------
def display_image(image_path="cisp.jpg", max_height="180px"):
    try:
        if os.path.exists(image_path):
            with open(image_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            ext = image_path.rsplit(".", 1)[-1].lower()
            mime = "image/png" if ext == "png" else "image/jpeg"
            st.markdown(
                f"""<div style="text-align:center; margin-bottom:18px;">
                    <img src="data:{mime};base64,{b64}"
                         style="max-width:100%; max-height:{max_height};
                                border-radius:12px;
                                box-shadow:0 4px 16px rgba(0,0,0,0.35);">
                </div>""",
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""<div style="text-align:center; margin-bottom:18px;">
                    <div style="background:linear-gradient(135deg,#0f1724,#071426);
                                height:120px; border-radius:12px; display:flex;
                                align-items:center; justify-content:center;
                                color:white; font-size:1.6rem; font-weight:700;
                                box-shadow:0 4px 16px rgba(0,0,0,0.35);">
                        🛡️ CISP Governance
                    </div>
                </div>""",
                unsafe_allow_html=True
            )
    except Exception as e:
        st.error(f"Erro ao carregar imagem: {e}")

# --------------------------
# Global CSS
# --------------------------
GLOBAL_CSS = """
<style>
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1b2a 0%, #112240 100%);
    border-right: 1px solid #1e3a5f;
}
[data-testid="stSidebar"] * { color: #cdd9e5 !important; }
[data-testid="stSidebar"] hr { border-color: #1e3a5f; }

[data-testid="metric-container"] {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px;
    padding: 16px !important;
}
[data-testid="stExpander"] {
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 8px;
}
[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }

.alert-banner {
    background: linear-gradient(90deg,#7f1d1d22,#7f1d1d11);
    border-left: 4px solid #ef4444; border-radius:6px;
    padding:10px 16px; margin-bottom:10px;
    font-size:.88rem; color:#fca5a5;
}
.warn-banner {
    background: linear-gradient(90deg,#78350f22,#78350f11);
    border-left: 4px solid #f59e0b; border-radius:6px;
    padding:10px 16px; margin-bottom:10px;
    font-size:.88rem; color:#fcd34d;
}
.pulse {
    display:inline-block; width:10px; height:10px;
    border-radius:50%; background:#2bd37b;
    box-shadow:0 0 0 rgba(43,211,123,.7);
    animation:pulse 1.8s infinite; margin-right:7px;
}
@keyframes pulse {
    0%  { box-shadow:0 0 0 0 rgba(43,211,123,.7); }
    70% { box-shadow:0 0 0 9px rgba(43,211,123,0); }
    100%{ box-shadow:0 0 0 0 rgba(43,211,123,0); }
}
</style>
"""

# --------------------------
# Login UI
# --------------------------
def login_ui():
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
    _, col, _ = st.columns([1, 2, 1])
    with col:
        # Imagem CISP na página de login
        display_image("cisp.jpg", max_height="200px")

        st.markdown("""
        <div style="background:linear-gradient(135deg,#0f1724,#071426);
                    border-radius:12px; padding:18px; color:white; margin-bottom:18px;">
            <span class="pulse"></span>
            <strong>🔐 CISP — Plataforma de Governança</strong>
            <div style="font-size:.78rem; margin-top:5px; opacity:.7;">
                Segurança · Riscos · Proteção de Dados
            </div>
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("👤 Utilizador", placeholder="Login")
            password = st.text_input("🔑 Senha", type="password", placeholder="Senha")
            submitted = st.form_submit_button("Entrar →", use_container_width=True)

            if submitted:
                with engine.connect() as conn:
                    row = conn.execute(
                        select(users.c.id, users.c.username, users.c.password_hash,
                               users.c.role, users.c.full_name, users.c.is_active)
                        .where(users.c.username == username)
                    ).first()

                if row and row.is_active and verify_password(password, row.password_hash):
                    st.session_state["user"] = {
                        "id": row.id, "username": row.username,
                        "role": row.role, "full_name": row.full_name
                    }
                    with engine.connect() as conn:
                        conn.execute(users.update().where(users.c.id == row.id)
                                     .values(last_login=datetime.utcnow()))
                        conn.commit()
                    log_access(row.username, row.role, "login", "Login bem-sucedido")
                    st.rerun()
                elif row and not row.is_active:
                    st.error("Utilizador desativado. Contacte o administrador.")
                    log_access(username, "", "failed_login", "Utilizador desativado")
                else:
                    st.error("Utilizador ou senha inválidos")
                    if row:
                        log_access(username, row.role, "failed_login", "Credenciais inválidas")

        st.markdown("""<p style="text-align:center;color:#4b5563;font-size:.75rem;margin-top:14px;">
            Acesso restrito a utilizadores autorizados</p>""", unsafe_allow_html=True)

# --------------------------
# Sidebar navigation
# --------------------------
def sidebar_nav(user):
    with st.sidebar:
        # Imagem CISP na sidebar
        display_image("cisp.jpg", max_height="90px")

        st.markdown(f"""
        <div style="padding:0 0 12px;">
            <div style="font-size:.78rem;opacity:.5;text-transform:uppercase;
                        letter-spacing:.6px;margin-bottom:4px;">Utilizador</div>
            <div style="font-size:.92rem;font-weight:600;">
                {user['full_name'] or user['username']}</div>
            <div style="font-size:.75rem;opacity:.55;">
                {user['role'].upper()}</div>
        </div>
        <hr>
        """, unsafe_allow_html=True)

        menu_items = ["📊 Dashboard"]
        if user["role"] in ("admin", "gestor"):
            menu_items.append("📘 Políticas")
        if user["role"] in ("admin", "gestor", "analista"):
            menu_items.append("🗂️ Ativos & Riscos")
        if user["role"] in ("admin", "gestor", "analista", "auditor"):
            menu_items.append("🚨 Incidentes")
        if user["role"] in ("admin", "gestor", "analista"):
            menu_items.append("📄 Proteção de Dados")
        if user["role"] in ("admin", "gestor", "auditor"):
            menu_items.append("🔍 Auditorias")
        if user["role"] in ("admin", "gestor", "analista"):
            menu_items.append("🎓 Treinamentos")
            menu_items.append("🤖 Detecção Automática")
        if user["role"] == "admin":
            menu_items.append("⚙️ Administração")

        # Preserve navigation from quick-action buttons
        default_idx = 0
        if "nav" in st.session_state and st.session_state["nav"] in menu_items:
            default_idx = menu_items.index(st.session_state["nav"])
            del st.session_state["nav"]

        choice = st.radio("Navegação", menu_items,
                          index=default_idx, label_visibility="collapsed")

        st.markdown("<hr>", unsafe_allow_html=True)
        if st.button("🚪 Sair", use_container_width=True):
            log_access(user["username"], user["role"], "logout")
            del st.session_state["user"]
            st.rerun()

    return choice

# --------------------------
# Dashboard
# --------------------------
def page_dashboard():
    st.title("📊 Painel de Controlo")

    with engine.connect() as conn:
        pol_count  = conn.execute(select(func.count()).select_from(policies)).scalar() or 0
        risk_count = conn.execute(select(func.count()).select_from(risks)).scalar() or 0
        inc_count  = conn.execute(select(func.count()).select_from(incidents)).scalar() or 0
        dsar_count = conn.execute(select(func.count()).select_from(dsar)).scalar() or 0
        risk_rows  = pd.read_sql(select(risks), conn)
        inc_rows   = pd.read_sql(select(incidents), conn)
        dsar_rows  = pd.read_sql(select(dsar), conn)
        pol_rows   = pd.read_sql(select(policies), conn)

    # --- Alertas de prazo ---
    alerts = []
    if not dsar_rows.empty:
        overdue = dsar_rows[dsar_rows.apply(lambda r:
            r["status"] not in ("Respondido","Encerrado","Indeferido") and
            r["due_date"] is not None and
            (days_overdue(r["due_date"]) or 0) > 0, axis=1)]
        if not overdue.empty:
            alerts.append(f'<div class="alert-banner">⚠️ {len(overdue)} solicitação(ões) DSAR com prazo vencido!</div>')

    if not inc_rows.empty:
        open_crit = inc_rows[
            (inc_rows["severity"] == "Crítica") &
            (~inc_rows["status"].isin(["Encerrado","Recuperado"]))
        ]
        if not open_crit.empty:
            alerts.append(f'<div class="alert-banner">🚨 {len(open_crit)} incidente(s) Crítico(s) em aberto!</div>')

    if not pol_rows.empty and "next_review_date" in pol_rows.columns:
        overdue_pol = pol_rows[pol_rows["next_review_date"].apply(
            lambda d: d is not None and (days_overdue(d) or 0) > 0)]
        if not overdue_pol.empty:
            alerts.append(f'<div class="warn-banner">📋 {len(overdue_pol)} política(s) com revisão vencida.</div>')

    if alerts:
        st.markdown("".join(alerts), unsafe_allow_html=True)

    # --- KPIs ---
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📘 Políticas", pol_count)
    c2.metric("⚠️ Riscos", risk_count)
    c3.metric("🚨 Incidentes", inc_count)
    c4.metric("📄 DSAR", dsar_count)

    st.divider()

    # --- Matriz de risco com quadrantes coloridos ---
    st.subheader("Matriz de Risco")
    if risk_rows.empty:
        st.info("Não há riscos cadastrados.")
    else:
        risk_rows["likelihood"] = risk_rows["likelihood"].astype(int)
        risk_rows["impact"]     = risk_rows["impact"].astype(int)
        risk_rows["size"]       = risk_rows["residual"].fillna(1).astype(int)

        bg = pd.DataFrame([
            {"x1":0.8,"x2":2.5,"y1":0.8,"y2":2.5,"zone":"Baixo"},
            {"x1":2.5,"x2":5.2,"y1":0.8,"y2":2.5,"zone":"Médio"},
            {"x1":0.8,"x2":2.5,"y1":2.5,"y2":5.2,"zone":"Médio"},
            {"x1":2.5,"x2":3.8,"y1":2.5,"y2":3.8,"zone":"Elevado"},
            {"x1":3.8,"x2":5.2,"y1":2.5,"y2":5.2,"zone":"Crítico"},
            {"x1":2.5,"x2":3.8,"y1":3.8,"y2":5.2,"zone":"Crítico"},
        ])
        zone_colors = {"Baixo":"#16a34a33","Médio":"#ca8a0433","Elevado":"#ea580c33","Crítico":"#dc262633"}
        rects = alt.Chart(bg).mark_rect(opacity=0.35).encode(
            x=alt.X("x1:Q", scale=alt.Scale(domain=(0.8,5.2))),
            x2="x2:Q",
            y=alt.Y("y1:Q", scale=alt.Scale(domain=(0.8,5.2))),
            y2="y2:Q",
            color=alt.Color("zone:N", scale=alt.Scale(
                domain=list(zone_colors.keys()), range=list(zone_colors.values())
            ), legend=None)
        )
        circles = alt.Chart(risk_rows).mark_circle(stroke="#fff", strokeWidth=1.2).encode(
            x=alt.X("likelihood:Q", title="Probabilidade"),
            y=alt.Y("impact:Q", title="Impacto"),
            size=alt.Size("size:Q", title="Risco Residual", scale=alt.Scale(range=[100,700])),
            color=alt.Color("status:N", title="Status"),
            tooltip=["id","title","owner","controls","residual","status"]
        )
        st.altair_chart((rects + circles).properties(height=360), use_container_width=True)

    # --- Incidentes por severidade ---
    st.subheader("Incidentes por Severidade")
    if inc_rows.empty:
        st.info("Sem incidentes registados.")
    else:
        df_i = inc_rows.copy()
        df_i["severity"] = df_i["severity"].fillna("Desconhecida")
        cnt = df_i.groupby("severity").size().reset_index(name="count")
        color_map = {"Crítica":"#ef4444","Alta":"#f97316","Média":"#3b82f6",
                     "Baixa":"#22c55e","Desconhecida":"#6b7280"}
        bar = alt.Chart(cnt).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
            x=alt.X("severity:N", sort=["Crítica","Alta","Média","Baixa"]),
            y="count:Q",
            color=alt.Color("severity:N", scale=alt.Scale(
                domain=list(color_map.keys()), range=list(color_map.values())
            ), legend=None),
            tooltip=["severity","count"]
        ).properties(height=260)
        st.altair_chart(bar, use_container_width=True)

    # --- DSAR donut ---
    if not dsar_rows.empty:
        st.subheader("DSAR por Status")
        ds = dsar_rows.groupby("status").size().reset_index(name="count")
        donut = alt.Chart(ds).mark_arc(innerRadius=55).encode(
            theta="count:Q",
            color=alt.Color("status:N", title="Status"),
            tooltip=["status","count"]
        ).properties(height=250)
        st.altair_chart(donut, use_container_width=True)

    st.divider()
    st.markdown("#### ⚡ Ações rápidas")
    c1, c2, c3 = st.columns(3)
    if c1.button("➕ Novo Risco", use_container_width=True):
        st.session_state["nav"] = "🗂️ Ativos & Riscos"
        st.rerun()
    if c2.button("➕ Novo Incidente", use_container_width=True):
        st.session_state["nav"] = "🚨 Incidentes"
        st.rerun()
    if c3.button("➕ Registrar DSAR", use_container_width=True):
        st.session_state["nav"] = "📄 Proteção de Dados"
        st.rerun()

# --------------------------
@require_roles(("gestor",))
def page_policies():
    st.title("📘 Políticas")

    with engine.connect() as conn:
        df = pd.read_sql(select(policies), conn)

    # Filtros
    c1, c2 = st.columns([3,1])
    search = c1.text_input("🔎 Buscar política", placeholder="Título, responsável…")
    status_f = c2.selectbox("Status", ["Todos","Rascunho","Aprovada","Obsoleta"])

    display = df.copy()
    if search:
        display = display[
            display["title"].str.contains(search, case=False, na=False) |
            display["owner"].str.contains(search, case=False, na=False)
        ]
    if status_f != "Todos":
        display = display[display["status"] == status_f]

    sort_col = "updated_at" if "updated_at" in df.columns else "id"
    cols_show = ["id","title","version","owner","status","effective_date","next_review_date"]
    st.dataframe(
        display.sort_values(sort_col, ascending=False)[cols_show],
        use_container_width=True, hide_index=True
    )

    with st.expander("➕ Criar nova política"):
        with st.form("policy_create"):
            title   = st.text_input("Título")
            version = st.text_input("Versão", "1.0")
            owner   = st.text_input("Responsável",
                st.session_state["user"]["full_name"] or st.session_state["user"]["username"])
            c1, c2 = st.columns(2)
            classification = c1.selectbox("Classificação", ["Interna","Restrita","Pública"])
            status  = c2.selectbox("Status", ["Rascunho","Aprovada","Obsoleta"])
            scope   = st.text_area("Escopo", "Todos os colaboradores e sistemas")
            c3, c4  = st.columns(2)
            eff     = c3.date_input("Vigência", value=date.today())
            next_rev= c4.date_input("Próxima revisão",
                value=date(date.today().year+1, date.today().month, date.today().day))
            body    = st.text_area("Conteúdo", value="(Insira o texto da política)", height=180)
            if st.form_submit_button("💾 Salvar política", use_container_width=True):
                if not title.strip():
                    st.warning("Título é obrigatório.")
                else:
                    with engine.connect() as conn:
                        res = conn.execute(policies.insert().values(
                            title=title, version=version, owner=owner,
                            classification=classification, scope=scope, status=status,
                            effective_date=eff, next_review_date=next_rev, body=body,
                            created_at=datetime.utcnow(), updated_at=datetime.utcnow()
                        ))
                        conn.commit()
                        new_id = res.inserted_primary_key[0]
                    log_action(
                        actor=st.session_state["user"]["username"],
                        role=st.session_state["user"]["role"],
                        action="create_policy", target_table="policies", target_id=new_id,
                        new_values={"title":title,"version":version,"owner":owner,"status":status},
                        details=f"Política criada: {title}"
                    )
                    st.success("✅ Política criada!")
                    st.rerun()

    if not df.empty:
        with st.expander("✏️ Editar ou excluir política existente"):
            opts = [f"{r.id} - {r.title}" for r in df.itertuples()]
            sel  = st.selectbox("Selecione a política", [""] + opts)
            if sel:
                pid  = int(sel.split(" - ")[0])
                row  = get_row(policies, pid)
                if row:
                    with st.form("policy_edit"):
                        title   = st.text_input("Título", value=row["title"])
                        version = st.text_input("Versão", value=row["version"])
                        owner   = st.text_input("Responsável", value=row["owner"])
                        c1, c2  = st.columns(2)
                        cl_opts = ["Interna","Restrita","Pública"]
                        classification = c1.selectbox("Classificação", cl_opts,
                            index=cl_opts.index(row["classification"]) if row["classification"] in cl_opts else 0)
                        st_opts = ["Rascunho","Aprovada","Obsoleta"]
                        status  = c2.selectbox("Status", st_opts,
                            index=st_opts.index(row["status"]) if row["status"] in st_opts else 0)
                        scope   = st.text_area("Escopo", value=row["scope"] or "")
                        c3, c4  = st.columns(2)
                        eff     = c3.date_input("Vigência", value=row["effective_date"] or date.today())
                        next_rev= c4.date_input("Próxima revisão", value=row["next_review_date"] or date.today())
                        body    = st.text_area("Conteúdo", value=row["body"] or "", height=180)
                        ca, cb  = st.columns(2)
                        save    = ca.form_submit_button("💾 Salvar", use_container_width=True)
                        delete  = cb.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                        if save:
                            old = {k: str(row[k]) for k in ["title","version","status","owner"]}
                            update_row(policies, pid, {
                                "title":title,"version":version,"owner":owner,
                                "classification":classification,"scope":scope,"status":status,
                                "effective_date":eff,"next_review_date":next_rev,
                                "body":body,"updated_at":datetime.utcnow()
                            })
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "update_policy","policies",pid,
                                       old_values=old,
                                       new_values={"title":title,"status":status},
                                       details=f"Política editada: {title}")
                            st.success("✅ Política atualizada")
                            st.rerun()
                        if delete:
                            delete_row(policies, pid)
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "delete_policy","policies",pid,
                                       old_values={"title":row["title"]},
                                       details=f"Política excluída: {row['title']}")
                            st.success("🗑️ Política excluída")
                            st.rerun()

# --------------------------
@require_roles(("analista","gestor"))
def page_assets_risks():
    st.title("🗂️ Ativos e Riscos")
    tabs = st.tabs(["📦 Ativos", "⚠️ Riscos"])

    with engine.connect() as conn:
        assets_df = pd.read_sql(select(assets), conn)

    # --- Ativos ---
    with tabs[0]:
        st.subheader("Ativos")
        search_a = st.text_input("🔎 Buscar ativo", key="search_asset")
        disp_a = assets_df[
            assets_df["name"].str.contains(search_a, case=False, na=False) |
            assets_df["type"].str.contains(search_a, case=False, na=False)
        ] if search_a else assets_df
        st.dataframe(disp_a, use_container_width=True, hide_index=True)

        with st.form("asset_create"):
            c1, c2 = st.columns(2)
            name = c1.text_input("Nome do ativo")
            atype = c2.selectbox("Tipo", ["Informação","Aplicação","Infraestrutura","Físico","Pessoa"])
            c3, c4 = st.columns(2)
            owner = c3.text_input("Responsável")
            criticality = c4.selectbox("Criticidade", ["Baixa","Média","Alta","Crítica"])
            if st.form_submit_button("➕ Adicionar Ativo", use_container_width=True):
                if not name.strip():
                    st.warning("Nome é obrigatório.")
                else:
                    with engine.connect() as conn:
                        res = conn.execute(assets.insert().values(
                            name=name, type=atype, owner=owner, criticality=criticality))
                        conn.commit()
                        new_id = res.inserted_primary_key[0]
                    log_action(st.session_state["user"]["username"],
                               st.session_state["user"]["role"],
                               "create_asset","assets",new_id,
                               new_values={"name":name,"type":atype,"owner":owner,"criticality":criticality},
                               details=f"Ativo criado: {name}")
                    st.success("✅ Ativo adicionado")
                    st.rerun()

        if not assets_df.empty:
            with st.expander("✏️ Editar ou excluir ativo"):
                opts = [f"{r.id} - {r.name}" for r in assets_df.itertuples()]
                sel  = st.selectbox("Selecione o ativo", [""] + opts)
                if sel:
                    aid = int(sel.split(" - ")[0])
                    row = get_row(assets, aid)
                    if row:
                        with st.form("asset_edit"):
                            c1, c2 = st.columns(2)
                            name = c1.text_input("Nome", value=row["name"])
                            ty_opts = ["Informação","Aplicação","Infraestrutura","Físico","Pessoa"]
                            atype = c2.selectbox("Tipo", ty_opts,
                                index=ty_opts.index(row["type"]) if row["type"] in ty_opts else 0)
                            c3, c4 = st.columns(2)
                            owner = c3.text_input("Responsável", value=row["owner"])
                            cr_opts = ["Baixa","Média","Alta","Crítica"]
                            criticality = c4.selectbox("Criticidade", cr_opts,
                                index=cr_opts.index(row["criticality"]) if row["criticality"] in cr_opts else 0)
                            ca, cb = st.columns(2)
                            save   = ca.form_submit_button("💾 Salvar", use_container_width=True)
                            delete = cb.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                            if save:
                                update_row(assets, aid, {"name":name,"type":atype,"owner":owner,"criticality":criticality})
                                log_action(st.session_state["user"]["username"],
                                           st.session_state["user"]["role"],
                                           "update_asset","assets",aid,
                                           old_values={"name":row["name"]},
                                           new_values={"name":name,"criticality":criticality})
                                st.success("✅ Ativo atualizado"); st.rerun()
                            if delete:
                                delete_row(assets, aid)
                                log_action(st.session_state["user"]["username"],
                                           st.session_state["user"]["role"],
                                           "delete_asset","assets",aid,
                                           old_values={"name":row["name"]})
                                st.success("🗑️ Ativo excluído"); st.rerun()

    # --- Riscos ---
    with tabs[1]:
        with engine.connect() as conn:
            risks_df = pd.read_sql(select(risks), conn)
            asset_opts = pd.read_sql(select(assets.c.id, assets.c.name), conn)

        st.subheader("Riscos")
        c1, c2 = st.columns([3,1])
        search_r = c1.text_input("🔎 Buscar risco", key="search_risk")
        cat_f    = c2.selectbox("Categoria", ["Todas","Cibernético","Operacional","Físico","Terceiros","Compliance"])
        disp_r = risks_df.copy()
        if search_r:
            disp_r = disp_r[disp_r["title"].str.contains(search_r, case=False, na=False)]
        if cat_f != "Todas":
            disp_r = disp_r[disp_r["category"] == cat_f]
        st.dataframe(disp_r, use_container_width=True, hide_index=True)

        with st.form("risk_create"):
            title       = st.text_input("Título do risco")
            description = st.text_area("Descrição", height=70)
            c1, c2  = st.columns(2)
            a_choice= c1.selectbox("Ativo (opcional)", ["Nenhum"] + asset_opts["name"].tolist())
            category= c2.selectbox("Categoria", ["Cibernético","Operacional","Físico","Terceiros","Compliance"])
            asset_id = None
            if a_choice != "Nenhum" and not asset_opts.empty:
                asset_id = int(asset_opts[asset_opts["name"] == a_choice].id.iloc[0])
            c3, c4  = st.columns(2)
            likelihood = c3.slider("Probabilidade (1-5)", 1, 5, 3)
            impact     = c4.slider("Impacto (1-5)", 1, 5, 3)
            inherent   = likelihood * impact
            st.info(f"Risco inerente: **{inherent}**")
            controls = st.text_area("Controles aplicados", height=60)
            residual = st.slider("Risco residual (1-25)", 1, 25, inherent)
            c5, c6   = st.columns(2)
            owner    = c5.text_input("Responsável")
            st_opts  = ["Aberto","Mitigando","Aceito","Transferido","Encerrado"]
            status   = c6.selectbox("Status", st_opts)
            rev_date = st.date_input("Data de revisão", value=date.today())
            if st.form_submit_button("➕ Registrar Risco", use_container_width=True):
                if not title.strip():
                    st.warning("Título é obrigatório.")
                else:
                    with engine.connect() as conn:
                        res = conn.execute(risks.insert().values(
                            title=title, description=description, asset_id=asset_id,
                            category=category, likelihood=likelihood, impact=impact,
                            inherent=inherent, controls=controls, residual=residual,
                            owner=owner, status=status, review_date=rev_date,
                            created_at=datetime.utcnow()
                        ))
                        conn.commit()
                        new_id = res.inserted_primary_key[0]
                    log_action(st.session_state["user"]["username"],
                               st.session_state["user"]["role"],
                               "create_risk","risks",new_id,
                               new_values={"title":title,"category":category,"owner":owner,"status":status},
                               details=f"Risco criado: {title}")
                    st.success("✅ Risco registado"); st.rerun()

        if not risks_df.empty:
            with st.expander("✏️ Editar ou excluir risco"):
                opts = [f"{r.id} - {r.title}" for r in risks_df.itertuples()]
                sel  = st.selectbox("Selecione o risco", [""] + opts)
                if sel:
                    rid = int(sel.split(" - ")[0])
                    row = get_row(risks, rid)
                    if row:
                        with st.form("risk_edit"):
                            title       = st.text_input("Título", value=row["title"])
                            description = st.text_area("Descrição", value=row["description"] or "", height=70)
                            c1, c2      = st.columns(2)
                            a_choice    = c1.selectbox("Ativo (opcional)",
                                ["Nenhum"] + asset_opts["name"].tolist(),
                                index=(asset_opts[asset_opts["id"]==row["asset_id"]].index[0]+1)
                                if row["asset_id"] in asset_opts["id"].tolist() else 0)
                            asset_id = None
                            if a_choice != "Nenhum":
                                asset_id = int(asset_opts[asset_opts["name"]==a_choice].id.iloc[0])
                            cat_opts = ["Cibernético","Operacional","Físico","Terceiros","Compliance"]
                            category = c2.selectbox("Categoria", cat_opts,
                                index=cat_opts.index(row["category"]) if row["category"] in cat_opts else 0)
                            c3, c4   = st.columns(2)
                            likelihood = c3.slider("Probabilidade", 1, 5, int(row["likelihood"] or 3))
                            impact     = c4.slider("Impacto", 1, 5, int(row["impact"] or 3))
                            inherent   = likelihood * impact
                            controls = st.text_area("Controles", value=row["controls"] or "", height=60)
                            residual = st.slider("Risco residual", 1, 25, int(row["residual"] or inherent))
                            c5, c6   = st.columns(2)
                            owner    = c5.text_input("Responsável", value=row["owner"] or "")
                            st_opts  = ["Aberto","Mitigando","Aceito","Transferido","Encerrado"]
                            status   = c6.selectbox("Status", st_opts,
                                index=st_opts.index(row["status"]) if row["status"] in st_opts else 0)
                            rev_date = st.date_input("Revisão", value=row["review_date"] or date.today())
                            ca, cb   = st.columns(2)
                            save     = ca.form_submit_button("💾 Salvar", use_container_width=True)
                            delete   = cb.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                            if save:
                                old = {k: str(row[k]) for k in ["title","status","likelihood","impact"]}
                                update_row(risks, rid, {
                                    "title":title,"description":description,"asset_id":asset_id,
                                    "category":category,"likelihood":likelihood,"impact":impact,
                                    "inherent":inherent,"controls":controls,"residual":residual,
                                    "owner":owner,"status":status,"review_date":rev_date
                                })
                                log_action(st.session_state["user"]["username"],
                                           st.session_state["user"]["role"],
                                           "update_risk","risks",rid,
                                           old_values=old,
                                           new_values={"title":title,"status":status})
                                st.success("✅ Risco atualizado"); st.rerun()
                            if delete:
                                delete_row(risks, rid)
                                log_action(st.session_state["user"]["username"],
                                           st.session_state["user"]["role"],
                                           "delete_risk","risks",rid,
                                           old_values={"title":row["title"]})
                                st.success("🗑️ Risco excluído"); st.rerun()

# --------------------------
@require_roles(("analista","gestor","auditor"))
def page_incidents():
    st.title("🚨 Incidentes")

    with engine.connect() as conn:
        df = pd.read_sql(select(incidents), conn)

    c1, c2 = st.columns([3,1])
    search_i = c1.text_input("🔎 Buscar incidente")
    sev_f    = c2.selectbox("Severidade", ["Todas","Crítica","Alta","Média","Baixa"])
    disp_i = df.copy()
    if search_i:
        disp_i = disp_i[disp_i["title"].str.contains(search_i, case=False, na=False)]
    if sev_f != "Todas":
        disp_i = disp_i[disp_i["severity"] == sev_f]
    if not disp_i.empty:
        disp_i = disp_i.sort_values("detected_at", ascending=False)
    st.dataframe(disp_i, use_container_width=True, hide_index=True)

    with st.expander("➕ Registrar novo incidente"):
        with st.form("inc_form"):
            title    = st.text_input("Título")
            c1, c2   = st.columns(2)
            severity = c1.selectbox("Severidade", ["Baixa","Média","Alta","Crítica"])
            category = c2.selectbox("Categoria",
                ["Dados Pessoais","Malware","Disponibilidade","Acesso Indevido","Outros"])
            c3, c4   = st.columns(2)
            det_date = c3.date_input("Data de detecção", value=date.today())
            det_time = c4.time_input("Hora de detecção", value=datetime.now().time())
            detected_at = datetime.combine(det_date, det_time)
            status = st.selectbox("Status",
                ["Aberto","Contido","Erradicado","Recuperado","Encerrado"])
            description = st.text_area("Descrição", height=70)
            root_cause  = st.text_area("Causa raiz", height=60)
            lessons     = st.text_area("Lições aprendidas", height=60)
            notif_req   = st.checkbox("Requer notificação à autoridade/titulares")
            notified_at = None
            if notif_req:
                c5, c6 = st.columns(2)
                notified_at = datetime.combine(
                    c5.date_input("Data de notificação", value=date.today()),
                    c6.time_input("Hora de notificação", value=datetime.now().time())
                )
            if st.form_submit_button("➕ Registrar incidente", use_container_width=True):
                if not title.strip():
                    st.warning("Título é obrigatório.")
                else:
                    with engine.connect() as conn:
                        res = conn.execute(incidents.insert().values(
                            title=title, severity=severity, category=category,
                            detected_at=detected_at, status=status,
                            description=description, root_cause=root_cause,
                            lessons_learned=lessons,
                            notification_required=bool(notif_req),
                            notified_at=notified_at, created_at=datetime.utcnow()
                        ))
                        conn.commit()
                        new_id = res.inserted_primary_key[0]
                    log_action(st.session_state["user"]["username"],
                               st.session_state["user"]["role"],
                               "create_incident","incidents",new_id,
                               new_values={"title":title,"severity":severity,"status":status},
                               details=f"Incidente criado: {title}")
                    st.success("✅ Incidente registado"); st.rerun()

    if not df.empty:
        with st.expander("✏️ Editar ou excluir incidente"):
            opts = [f"{r.id} - {r.title}" for r in df.itertuples()]
            sel  = st.selectbox("Selecione o incidente", [""] + opts)
            if sel:
                iid = int(sel.split(" - ")[0])
                row = get_row(incidents, iid)
                if row:
                    with st.form("incident_edit"):
                        title    = st.text_input("Título", value=row["title"])
                        c1, c2   = st.columns(2)
                        sv_opts  = ["Baixa","Média","Alta","Crítica"]
                        severity = c1.selectbox("Severidade", sv_opts,
                            index=sv_opts.index(row["severity"]) if row["severity"] in sv_opts else 0)
                        ct_opts  = ["Dados Pessoais","Malware","Disponibilidade","Acesso Indevido","Outros"]
                        category = c2.selectbox("Categoria", ct_opts,
                            index=ct_opts.index(row["category"]) if row["category"] in ct_opts else 0)
                        c3, c4   = st.columns(2)
                        det_date = c3.date_input("Data detecção",
                            value=row["detected_at"].date() if row["detected_at"] else date.today())
                        det_time = c4.time_input("Hora detecção",
                            value=row["detected_at"].time() if row["detected_at"] else datetime.now().time())
                        detected_at = datetime.combine(det_date, det_time)
                        st_opts  = ["Aberto","Contido","Erradicado","Recuperado","Encerrado"]
                        status   = st.selectbox("Status", st_opts,
                            index=st_opts.index(row["status"]) if row["status"] in st_opts else 0)
                        description = st.text_area("Descrição", value=row["description"] or "", height=70)
                        root_cause  = st.text_area("Causa raiz", value=row["root_cause"] or "", height=60)
                        lessons     = st.text_area("Lições aprendidas", value=row["lessons_learned"] or "", height=60)
                        notif_req   = st.checkbox("Requer notificação", value=bool(row["notification_required"]))
                        notified_at = row["notified_at"]
                        if notif_req:
                            c5, c6 = st.columns(2)
                            notified_at = datetime.combine(
                                c5.date_input("Data notificação",
                                    value=row["notified_at"].date() if row["notified_at"] else date.today()),
                                c6.time_input("Hora notificação",
                                    value=row["notified_at"].time() if row["notified_at"] else datetime.now().time())
                            )
                        else:
                            notified_at = None
                        ca, cb = st.columns(2)
                        save   = ca.form_submit_button("💾 Salvar", use_container_width=True)
                        delete = cb.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                        if save:
                            old = {k: str(row[k]) for k in ["title","severity","status"]}
                            update_row(incidents, iid, {
                                "title":title,"severity":severity,"category":category,
                                "detected_at":detected_at,"status":status,
                                "description":description,"root_cause":root_cause,
                                "lessons_learned":lessons,
                                "notification_required":bool(notif_req),
                                "notified_at":notified_at
                            })
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "update_incident","incidents",iid,
                                       old_values=old,
                                       new_values={"title":title,"severity":severity,"status":status})
                            st.success("✅ Incidente atualizado"); st.rerun()
                        if delete:
                            delete_row(incidents, iid)
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "delete_incident","incidents",iid,
                                       old_values={"title":row["title"]})
                            st.success("🗑️ Incidente excluído"); st.rerun()

# --------------------------
@require_roles(("gestor","analista"))
def page_privacy():
    st.title("📄 Proteção de Dados — DSAR")

    with engine.connect() as conn:
        df = pd.read_sql(select(dsar), conn)

    # Indicadores de prazo
    if not df.empty:
        df["⚠️"] = df.apply(lambda r: "🔴 Vencido" if (
            r["status"] not in ("Respondido","Encerrado","Indeferido") and
            r["due_date"] is not None and (days_overdue(r["due_date"]) or 0) > 0
        ) else ("🟡 Próximo" if (
            r["due_date"] is not None and
            -7 <= (days_overdue(r["due_date"]) or -99) <= 0 and
            r["status"] not in ("Respondido","Encerrado","Indeferido")
        ) else "✅"), axis=1)

    c1, c2 = st.columns([3,1])
    search_d = c1.text_input("🔎 Buscar titular ou tipo")
    status_f = c2.selectbox("Status", ["Todos","Aberto","Em Análise","Respondido","Encerrado","Indeferido"])
    disp_d = df.copy()
    if search_d:
        disp_d = disp_d[
            disp_d["requester"].str.contains(search_d, case=False, na=False) |
            disp_d["type"].str.contains(search_d, case=False, na=False)
        ]
    if status_f != "Todos":
        disp_d = disp_d[disp_d["status"] == status_f]
    st.dataframe(disp_d, use_container_width=True, hide_index=True)

    with st.form("dsar_form"):
        c1, c2    = st.columns(2)
        requester = c1.text_input("Titular")
        dtype     = c2.selectbox("Tipo", ["Acesso","Correção","Exclusão","Portabilidade","Oposição"])
        c3, c4    = st.columns(2)
        received  = c3.date_input("Recebido em", value=date.today())
        due       = c4.date_input("Prazo", value=date.today() + timedelta(days=15))
        status    = st.selectbox("Status", ["Aberto","Em Análise","Respondido","Encerrado","Indeferido"])
        notes     = st.text_area("Observações", height=60)
        if st.form_submit_button("➕ Registrar solicitação", use_container_width=True):
            if not requester.strip():
                st.warning("Nome do titular é obrigatório.")
            else:
                with engine.connect() as conn:
                    res = conn.execute(dsar.insert().values(
                        requester=requester, type=dtype, received_date=received,
                        due_date=due, status=status, notes=notes
                    ))
                    conn.commit()
                    new_id = res.inserted_primary_key[0]
                log_action(st.session_state["user"]["username"],
                           st.session_state["user"]["role"],
                           "create_dsar","dsar",new_id,
                           new_values={"requester":requester,"type":dtype,"status":status},
                           details=f"DSAR criada: {requester}")
                st.success("✅ Solicitação registada"); st.rerun()

    if not df.empty:
        with st.expander("✏️ Editar ou excluir solicitação"):
            opts = [f"{r.id} - {r.requester}" for r in df.itertuples()]
            sel  = st.selectbox("Selecione", [""] + opts)
            if sel:
                did = int(sel.split(" - ")[0])
                row = get_row(dsar, did)
                if row:
                    with st.form("dsar_edit"):
                        c1, c2    = st.columns(2)
                        requester = c1.text_input("Titular", value=row["requester"] or "")
                        ty_opts   = ["Acesso","Correção","Exclusão","Portabilidade","Oposição"]
                        dtype     = c2.selectbox("Tipo", ty_opts,
                            index=ty_opts.index(row["type"]) if row["type"] in ty_opts else 0)
                        c3, c4    = st.columns(2)
                        received  = c3.date_input("Recebido em", value=row["received_date"] or date.today())
                        due       = c4.date_input("Prazo", value=row["due_date"] or date.today())
                        st_opts   = ["Aberto","Em Análise","Respondido","Encerrado","Indeferido"]
                        status    = st.selectbox("Status", st_opts,
                            index=st_opts.index(row["status"]) if row["status"] in st_opts else 0)
                        notes     = st.text_area("Observações", value=row["notes"] or "", height=60)
                        ca, cb    = st.columns(2)
                        save      = ca.form_submit_button("💾 Salvar", use_container_width=True)
                        delete    = cb.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                        if save:
                            old = {k: str(row[k]) for k in ["requester","status"]}
                            update_row(dsar, did, {
                                "requester":requester,"type":dtype,"received_date":received,
                                "due_date":due,"status":status,"notes":notes
                            })
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "update_dsar","dsar",did,
                                       old_values=old,
                                       new_values={"requester":requester,"status":status})
                            st.success("✅ Atualizado"); st.rerun()
                        if delete:
                            delete_row(dsar, did)
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "delete_dsar","dsar",did,
                                       old_values={"requester":row["requester"]})
                            st.success("🗑️ Excluído"); st.rerun()

# --------------------------
@require_roles(("auditor","gestor","admin"))
def page_audits():
    st.title("🔍 Auditorias")

    with engine.connect() as conn:
        df = pd.read_sql(select(audits), conn)

    search_au = st.text_input("🔎 Buscar auditoria")
    disp_au = df[
        df["name"].str.contains(search_au, case=False, na=False)
    ] if search_au else df
    st.dataframe(disp_au, use_container_width=True, hide_index=True)

    with st.form("audit_form"):
        c1, c2 = st.columns([3,1])
        name   = c1.text_input("Nome da auditoria")
        adate  = c2.date_input("Data", value=date.today())
        scope    = st.text_area("Escopo", height=60)
        findings = st.text_area("Achados", height=60)
        status   = st.selectbox("Status", ["Planejada","Em Execução","Concluída"])
        if st.form_submit_button("➕ Registrar auditoria", use_container_width=True):
            if not name.strip():
                st.warning("Nome é obrigatório.")
            else:
                with engine.connect() as conn:
                    res = conn.execute(audits.insert().values(
                        name=name, audit_date=adate, scope=scope,
                        findings=findings, status=status
                    ))
                    conn.commit()
                    new_id = res.inserted_primary_key[0]
                log_action(st.session_state["user"]["username"],
                           st.session_state["user"]["role"],
                           "create_audit","audits",new_id,
                           new_values={"name":name,"status":status},
                           details=f"Auditoria criada: {name}")
                st.success("✅ Auditoria registada"); st.rerun()

    if not df.empty:
        with st.expander("✏️ Editar ou excluir auditoria"):
            opts = [f"{r.id} - {r.name}" for r in df.itertuples()]
            sel  = st.selectbox("Selecione", [""] + opts)
            if sel:
                aid = int(sel.split(" - ")[0])
                row = get_row(audits, aid)
                if row:
                    with st.form("audit_edit"):
                        c1, c2   = st.columns([3,1])
                        name     = c1.text_input("Nome", value=row["name"] or "")
                        adate    = c2.date_input("Data", value=row["audit_date"] or date.today())
                        scope    = st.text_area("Escopo", value=row["scope"] or "", height=60)
                        findings = st.text_area("Achados", value=row["findings"] or "", height=60)
                        st_opts  = ["Planejada","Em Execução","Concluída"]
                        status   = st.selectbox("Status", st_opts,
                            index=st_opts.index(row["status"]) if row["status"] in st_opts else 0)
                        ca, cb   = st.columns(2)
                        save     = ca.form_submit_button("💾 Salvar", use_container_width=True)
                        delete   = cb.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                        if save:
                            update_row(audits, aid, {"name":name,"audit_date":adate,
                                "scope":scope,"findings":findings,"status":status})
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "update_audit","audits",aid,
                                       old_values={"name":row["name"],"status":row["status"]},
                                       new_values={"name":name,"status":status})
                            st.success("✅ Atualizado"); st.rerun()
                        if delete:
                            delete_row(audits, aid)
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "delete_audit","audits",aid,
                                       old_values={"name":row["name"]})
                            st.success("🗑️ Excluído"); st.rerun()

# --------------------------
@require_roles(("gestor","analista"))
def page_trainings():
    st.title("🎓 Treinamentos")

    with engine.connect() as conn:
        df = pd.read_sql(select(trainings), conn)

    st.dataframe(df, use_container_width=True, hide_index=True)

    with st.form("training_form"):
        c1, c2   = st.columns(2)
        name     = c1.text_input("Treinamento")
        audience = c2.text_input("Público")
        c3, c4, c5 = st.columns(3)
        start_d  = c3.date_input("Início", value=date.today())
        end_d    = c4.date_input("Término", value=date.today())
        status   = c5.selectbox("Status", ["Planejada","Em Andamento","Concluída"])
        if st.form_submit_button("➕ Registrar treinamento", use_container_width=True):
            if not name.strip():
                st.warning("Nome é obrigatório.")
            else:
                with engine.connect() as conn:
                    res = conn.execute(trainings.insert().values(
                        name=name, audience=audience, start_date=start_d,
                        end_date=end_d, status=status
                    ))
                    conn.commit()
                    new_id = res.inserted_primary_key[0]
                log_action(st.session_state["user"]["username"],
                           st.session_state["user"]["role"],
                           "create_training","trainings",new_id,
                           new_values={"name":name,"status":status},
                           details=f"Treinamento criado: {name}")
                st.success("✅ Treinamento registado"); st.rerun()

    if not df.empty:
        with st.expander("✏️ Editar ou excluir treinamento"):
            opts = [f"{r.id} - {r.name}" for r in df.itertuples()]
            sel  = st.selectbox("Selecione", [""] + opts)
            if sel:
                tid = int(sel.split(" - ")[0])
                row = get_row(trainings, tid)
                if row:
                    with st.form("training_edit"):
                        c1, c2   = st.columns(2)
                        name     = c1.text_input("Treinamento", value=row["name"] or "")
                        audience = c2.text_input("Público", value=row["audience"] or "")
                        c3, c4, c5 = st.columns(3)
                        start_d  = c3.date_input("Início", value=row["start_date"] or date.today())
                        end_d    = c4.date_input("Término", value=row["end_date"] or date.today())
                        st_opts  = ["Planejada","Em Andamento","Concluída"]
                        status   = c5.selectbox("Status", st_opts,
                            index=st_opts.index(row["status"]) if row["status"] in st_opts else 0)
                        ca, cb   = st.columns(2)
                        save     = ca.form_submit_button("💾 Salvar", use_container_width=True)
                        delete   = cb.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                        if save:
                            update_row(trainings, tid, {"name":name,"audience":audience,
                                "start_date":start_d,"end_date":end_d,"status":status})
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "update_training","trainings",tid,
                                       old_values={"name":row["name"],"status":row["status"]},
                                       new_values={"name":name,"status":status})
                            st.success("✅ Atualizado"); st.rerun()
                        if delete:
                            delete_row(trainings, tid)
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "delete_training","trainings",tid,
                                       old_values={"name":row["name"]})
                            st.success("🗑️ Excluído"); st.rerun()

# --------------------------
# Detecção Automática
# --------------------------
@require_roles(("gestor","analista"))
def page_detect_autonomous():
    st.title("🤖 Detecção Automática de Riscos")
    st.info("Simulação de ingestão de eventos e geração automática de riscos. Dados fictícios.")

    event_types = [
        "Falha de Login","Acesso Fora do Horário","Pico de CPU","Pico de Rede",
        "Arquivo Suspeito Detetado","Serviço Vulnerável (CVE)",
        "Atividade Anómala de Utilizador","Erros Repetidos na Aplicação"
    ]
    origins    = ["Servidor A","Servidor B","Laptop XPTO","Firewall","API Interna","Estação RH"]
    severities = ["Baixa","Média","Alta","Crítica"]

    now = datetime.now()
    random.seed(42)
    logs_data = [{
        "timestamp": now - timedelta(minutes=random.randint(1, 8*60)),
        "evento":    random.choices(event_types, weights=[8,6,4,4,2,2,3,5])[0],
        "origem":    random.choice(origins),
        "severidade":random.choices(severities, weights=[3,4,2,1])[0]
    } for _ in range(60)]
    df_logs = pd.DataFrame(logs_data).sort_values("timestamp", ascending=False)

    rules = {
        "Falha de Login":                  ("Possível brute force — falhas de autenticação", "Alta"),
        "Acesso Fora do Horário":           ("Acesso suspeito fora do horário habitual", "Média"),
        "Arquivo Suspeito Detetado":        ("Arquivo potencialmente malicioso (EDR)", "Crítica"),
        "Pico de CPU":                      ("CPU anormal — possível DoS ou processo malicioso", "Alta"),
        "Pico de Rede":                     ("Tráfego incomum — possível exfiltração", "Alta"),
        "Serviço Vulnerável (CVE)":         ("Software com CVE conhecido em produção", "Crítica"),
        "Atividade Anómala de Utilizador":  ("Comportamento de utilizador fora do padrão", "Alta"),
        "Erros Repetidos na Aplicação":     ("Erros persistentes — risco de indisponibilidade", "Média"),
    }
    detected = [
        {"timestamp": r["timestamp"], "evento": r["evento"],
         "risco": rules[r["evento"]][0], "severidade": rules[r["evento"]][1],
         "origem": r["origem"]}
        for _, r in df_logs.iterrows() if r["evento"] in rules
    ]
    df_det = pd.DataFrame(detected).sort_values("timestamp", ascending=False) if detected else pd.DataFrame()

    tab_logs, tab_risks, tab_charts = st.tabs(["📡 Logs", "⚠️ Riscos Detetados", "📊 Gráficos"])

    with tab_logs:
        sev_f = st.selectbox("Filtrar severidade", ["Todas","Crítica","Alta","Média","Baixa"], key="log_sev")
        disp = df_logs[df_logs["severidade"]==sev_f] if sev_f!="Todas" else df_logs
        st.dataframe(disp, use_container_width=True, hide_index=True)

    with tab_risks:
        if df_det.empty:
            st.info("Nenhum risco detetado na simulação.")
        else:
            sev_f2 = st.selectbox("Filtrar severidade", ["Todas","Crítica","Alta","Média","Baixa"], key="det_sev")
            disp2 = df_det[df_det["severidade"]==sev_f2] if sev_f2!="Todas" else df_det
            st.dataframe(disp2, use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("#### ➕ Promover risco detetado para o Registo de Riscos")
            risk_det_opts = [f"{i} — {r['risco'][:55]}… ({r['severidade']})"
                             for i, r in df_det.iterrows()]
            sel_det = st.selectbox("Selecione o risco a promover", [""] + risk_det_opts)
            if sel_det:
                idx = int(sel_det.split(" — ")[0])
                sel_row = df_det.iloc[idx]
                with st.form("promote_form"):
                    st.write(f"**Evento:** {sel_row['evento']}  |  **Origem:** {sel_row['origem']}")
                    title_p = st.text_input("Título", value=sel_row["risco"][:80])
                    desc_p  = st.text_area("Descrição",
                        value=f"Detetado via simulação SIEM. Evento: {sel_row['evento']}. Origem: {sel_row['origem']}.",
                        height=70)
                    sev_map = {"Crítica":5,"Alta":4,"Média":3,"Baixa":2}
                    lk = sev_map.get(sel_row["severidade"], 3)
                    owner_p = st.text_input("Responsável",
                        value=st.session_state["user"]["full_name"] or st.session_state["user"]["username"])
                    if st.form_submit_button("✅ Registrar no Registo de Riscos", use_container_width=True):
                        with engine.connect() as conn:
                            res = conn.execute(risks.insert().values(
                                title=title_p, description=desc_p, category="Cibernético",
                                likelihood=lk, impact=lk, inherent=lk*lk,
                                controls="(A definir)", residual=lk*lk,
                                owner=owner_p, status="Aberto",
                                review_date=date.today()+timedelta(days=30),
                                created_at=datetime.utcnow()
                            ))
                            conn.commit()
                            new_id = res.inserted_primary_key[0]
                        log_action(st.session_state["user"]["username"],
                                   st.session_state["user"]["role"],
                                   "promote_detected_risk","risks",new_id,
                                   new_values={"title":title_p,"severity":sel_row["severidade"]},
                                   details="Risco promovido da detecção automática")
                        st.success(f"✅ Risco registado com ID #{new_id}! Aceda a Ativos & Riscos.")

    with tab_charts:
        if not df_det.empty:
            c1, c2 = st.columns(2)
            with c1:
                st.subheader("Por Severidade")
                sc = df_det["severidade"].value_counts().reset_index()
                sc.columns = ["severidade","count"]
                cm = {"Crítica":"#ef4444","Alta":"#f97316","Média":"#3b82f6","Baixa":"#22c55e"}
                bar = alt.Chart(sc).mark_bar(cornerRadiusTopLeft=4,cornerRadiusTopRight=4).encode(
                    x=alt.X("severidade:N",sort=["Crítica","Alta","Média","Baixa"]),
                    y="count:Q",
                    color=alt.Color("severidade:N",scale=alt.Scale(
                        domain=list(cm.keys()),range=list(cm.values())),legend=None),
                    tooltip=["severidade","count"]
                ).properties(height=250)
                st.altair_chart(bar, use_container_width=True)
            with c2:
                st.subheader("Por Origem")
                oc = df_det["origem"].value_counts().reset_index()
                oc.columns = ["origem","count"]
                pie = alt.Chart(oc).mark_arc(innerRadius=50).encode(
                    theta="count:Q",color="origem:N",tooltip=["origem","count"]
                ).properties(height=250)
                st.altair_chart(pie, use_container_width=True)

            st.subheader("Tendência temporal (por hora e severidade)")
            df_t = df_det.copy()
            df_t["hour"] = df_t["timestamp"].dt.floor("h")
            trend = df_t.groupby(["hour","severidade"]).size().reset_index(name="count")
            line = alt.Chart(trend).mark_line(point=True).encode(
                x=alt.X("hour:T",title="Hora"),
                y=alt.Y("count:Q",title="Nº riscos"),
                color="severidade:N",
                tooltip=["hour","severidade","count"]
            ).properties(height=260)
            st.altair_chart(line, use_container_width=True)

    st.success("✅ No ambiente real, eventos viriam via SIEM/EDR/CVE feeds.")

# --------------------------
# Administração
# --------------------------
@require_roles(("admin",))
def page_admin():
    st.title("⚙️ Administração do Sistema")

    tab_users, tab_access, tab_actions, tab_stats = st.tabs([
        "👥 Utilizadores", "🔐 Logs de Acesso", "📝 Logs de Ações", "📊 Estatísticas"
    ])

    # --- Utilizadores ---
    with tab_users:
        with engine.connect() as conn:
            users_df = pd.read_sql(select(
                users.c.id, users.c.username, users.c.role,
                users.c.full_name, users.c.is_active, users.c.last_login
            ), conn)
        st.dataframe(users_df, use_container_width=True, hide_index=True)

        c1, c2 = st.columns(2)
        with c1:
            with st.expander("➕ Criar novo utilizador"):
                with st.form("create_user"):
                    ca, cb = st.columns(2)
                    username = ca.text_input("Login")
                    fullname = cb.text_input("Nome completo")
                    cc, cd   = st.columns(2)
                    password = cc.text_input("Senha", type="password")
                    role     = cd.selectbox("Perfil", ["admin","gestor","analista","auditor"])
                    is_active= st.checkbox("Ativo", value=True)
                    if st.form_submit_button("➕ Criar", use_container_width=True):
                        if not username.strip() or not password.strip():
                            st.warning("Login e senha obrigatórios.")
                        else:
                            with engine.connect() as conn:
                                res = conn.execute(users.insert().values(
                                    username=username, password_hash=hash_password(password),
                                    role=role, full_name=fullname, is_active=is_active
                                ))
                                conn.commit()
                                new_id = res.inserted_primary_key[0]
                            log_action(st.session_state["user"]["username"],
                                       st.session_state["user"]["role"],
                                       "create_user","users",new_id,
                                       new_values={"username":username,"role":role},
                                       details=f"Utilizador criado: {username}")
                            st.success("✅ Utilizador criado"); st.rerun()

        with c2:
            with st.expander("✏️ Editar / desativar utilizador"):
                with st.form("edit_user"):
                    u_opts = [f"{r.id} - {r.username}" for r in users_df.itertuples()]
                    sel_u  = st.selectbox("Selecione", [""] + u_opts)
                    if sel_u:
                        uid    = int(sel_u.split(" - ")[0])
                        urow   = get_row(users, uid)
                        if urow:
                            ca, cb   = st.columns(2)
                            username = ca.text_input("Login", value=urow["username"])
                            fullname = cb.text_input("Nome", value=urow["full_name"] or "")
                            cc, cd   = st.columns(2)
                            password = cc.text_input("Senha (em branco = manter)", type="password")
                            role_opts= ["admin","gestor","analista","auditor"]
                            role     = cd.selectbox("Perfil", role_opts,
                                index=role_opts.index(urow["role"]) if urow["role"] in role_opts else 0)
                            is_active= st.checkbox("Ativo", value=bool(urow.get("is_active", True)))
                            ce, cf   = st.columns(2)
                            save_u   = ce.form_submit_button("💾 Salvar", use_container_width=True)
                            del_u    = cf.form_submit_button("🗑️ Excluir", use_container_width=True, type="primary")
                            if save_u:
                                vals = {"username":username,"role":role,
                                        "full_name":fullname,"is_active":is_active}
                                if password:
                                    vals["password_hash"] = hash_password(password)
                                update_row(users, uid, vals)
                                log_action(st.session_state["user"]["username"],
                                           st.session_state["user"]["role"],
                                           "update_user","users",uid,
                                           old_values={"username":urow["username"],"role":urow["role"]},
                                           new_values={"username":username,"role":role,"is_active":is_active})
                                st.success("✅ Atualizado"); st.rerun()
                            if del_u:
                                if uid == st.session_state["user"]["id"]:
                                    st.error("Não pode excluir a sua própria conta.")
                                else:
                                    delete_row(users, uid)
                                    log_action(st.session_state["user"]["username"],
                                               st.session_state["user"]["role"],
                                               "delete_user","users",uid,
                                               old_values={"username":urow["username"]})
                                    st.success("🗑️ Excluído"); st.rerun()
                    else:
                        st.form_submit_button("💾 Salvar", disabled=True, use_container_width=True)

    # --- Logs de Acesso ---
    with tab_access:
        st.subheader("Logs de Login / Logout")
        c1, c2, c3 = st.columns(3)
        f_user   = c1.text_input("Utilizador", key="f_acc_user")
        f_action = c2.selectbox("Ação", ["Todos","login","logout","failed_login"], key="f_acc_act")
        f_days   = c3.selectbox("Últimos dias", [1,7,30,90,365], index=2, key="f_acc_days")

        q = select(access_logs).order_by(access_logs.c.created_at.desc())
        if f_user:
            q = q.where(access_logs.c.username.ilike(f"%{f_user}%"))
        if f_action != "Todos":
            q = q.where(access_logs.c.action == f_action)
        q = q.where(access_logs.c.created_at >= datetime.utcnow() - timedelta(days=f_days))
        with engine.connect() as conn:
            acc_df = pd.read_sql(q.limit(500), conn)

        if not acc_df.empty:
            st.metric("Registos encontrados", len(acc_df))
            st.dataframe(
                acc_df[["created_at","username","role","action","ip_address","details"]]
                .rename(columns={"created_at":"Data/Hora","username":"Utilizador",
                                  "role":"Perfil","action":"Ação",
                                  "ip_address":"IP","details":"Detalhes"}),
                use_container_width=True, hide_index=True
            )
            c1, c2 = st.columns(2)
            with c1:
                acc_df["hour"] = pd.to_datetime(acc_df["created_at"]).dt.hour
                hc = acc_df.groupby("hour").size().reset_index(name="count")
                st.altair_chart(alt.Chart(hc).mark_bar().encode(
                    x=alt.X("hour:O", title="Hora"),
                    y=alt.Y("count:Q", title="Acessos"),
                    tooltip=["hour","count"]
                ).properties(height=220), use_container_width=True)
            with c2:
                ac = acc_df["action"].value_counts().reset_index()
                ac.columns = ["action","count"]
                st.altair_chart(alt.Chart(ac).mark_arc().encode(
                    theta="count:Q", color="action:N", tooltip=["action","count"]
                ).properties(height=220), use_container_width=True)
        else:
            st.info("Nenhum registo encontrado.")

    # --- Logs de Ações ---
    with tab_actions:
        st.subheader("Logs de Ações (CRUD)")
        c1, c2, c3 = st.columns(3)
        f_actor = c1.text_input("Executor", key="f_act_actor")
        f_table = c2.selectbox("Tabela",
            ["Todas","policies","assets","risks","incidents","dsar","audits","trainings","users"],
            key="f_act_table")
        f_atype = c3.text_input("Tipo de ação", key="f_act_type")

        q2 = select(audit_logs).order_by(audit_logs.c.created_at.desc())
        if f_actor: q2 = q2.where(audit_logs.c.actor.ilike(f"%{f_actor}%"))
        if f_table != "Todas": q2 = q2.where(audit_logs.c.target_table == f_table)
        if f_atype: q2 = q2.where(audit_logs.c.action.ilike(f"%{f_atype}%"))
        with engine.connect() as conn:
            aud_df = pd.read_sql(q2.limit(300), conn)

        if not aud_df.empty:
            def fmt_json(v):
                if v:
                    try: return json.dumps(json.loads(v), indent=2, ensure_ascii=False)
                    except: return v
                return "—"

            for _, r in aud_df.iterrows():
                with st.expander(
                    f"{r['created_at']}  |  **{r['actor']}** ({r['role']})  →  "
                    f"`{r['action']}` em `{r['target_table']}`"
                ):
                    ca, cb = st.columns(2)
                    with ca:
                        st.write("**Antes:**")
                        st.code(fmt_json(r["old_values"]), language="json")
                    with cb:
                        st.write("**Depois:**")
                        st.code(fmt_json(r["new_values"]), language="json")
                    st.caption(f"Detalhes: {r['details']}  |  IP: {r['ip_address']}")
        else:
            st.info("Nenhum log encontrado.")

    # --- Estatísticas ---
    with tab_stats:
        st.subheader("Estatísticas do Sistema")
        thirty_ago = datetime.utcnow() - timedelta(days=30)
        with engine.connect() as conn:
            total_users  = conn.execute(select(func.count()).select_from(users)).scalar()
            active_users = conn.execute(select(func.count()).select_from(users)
                                        .where(users.c.is_active == True)).scalar()
            total_logins = conn.execute(select(func.count()).select_from(access_logs)
                                        .where(access_logs.c.action=="login")).scalar()
            total_actions= conn.execute(select(func.count()).select_from(audit_logs)).scalar()
            recent_logins= conn.execute(select(func.count()).select_from(access_logs)
                                        .where(access_logs.c.action=="login")
                                        .where(access_logs.c.created_at>=thirty_ago)).scalar()
            recent_acts  = conn.execute(select(func.count()).select_from(audit_logs)
                                        .where(audit_logs.c.created_at>=thirty_ago)).scalar()

        c1, c2, c3 = st.columns(3)
        c1.metric("Utilizadores Ativos", active_users, f"Total: {total_users}")
        c2.metric("Logins (30 dias)", recent_logins, f"Total: {total_logins}")
        c3.metric("Ações (30 dias)", recent_acts, f"Total: {total_actions}")

        with engine.connect() as conn:
            daily = pd.read_sql(
                select(func.date(audit_logs.c.created_at).label("date"),
                       func.count().label("count"))
                .where(audit_logs.c.created_at >= thirty_ago)
                .group_by(func.date(audit_logs.c.created_at))
                .order_by(func.date(audit_logs.c.created_at)),
                conn
            )
            top_u = pd.read_sql(
                select(audit_logs.c.actor, audit_logs.c.role,
                       func.count().label("action_count"))
                .where(audit_logs.c.created_at >= thirty_ago)
                .group_by(audit_logs.c.actor, audit_logs.c.role)
                .order_by(func.count().desc()).limit(10),
                conn
            )

        if not daily.empty:
            st.subheader("Atividade por dia (30 dias)")
            st.altair_chart(alt.Chart(daily).mark_line(point=True).encode(
                x=alt.X("date:T", title="Data"),
                y=alt.Y("count:Q", title="Ações"),
                tooltip=["date","count"]
            ).properties(height=240), use_container_width=True)

        if not top_u.empty:
            st.subheader("Top 10 utilizadores por atividade")
            st.altair_chart(alt.Chart(top_u).mark_bar().encode(
                x=alt.X("action_count:Q", title="Nº de ações"),
                y=alt.Y("actor:N", sort="-x", title="Utilizador"),
                color=alt.Color("role:N", title="Perfil"),
                tooltip=["actor","role","action_count"]
            ).properties(height=300), use_container_width=True)

# --------------------------
# Main
# --------------------------
def main():
    st.set_page_config(page_title="CISP Governance", layout="wide", page_icon="🛡️")
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)
    bootstrap()

    if "user" not in st.session_state:
        st.session_state["user"] = None

    if not st.session_state["user"]:
        login_ui()
        return

    user = st.session_state["user"]
    choice = sidebar_nav(user)

    page_map = {
        "📊 Dashboard":           page_dashboard,
        "📘 Políticas":           page_policies,
        "🗂️ Ativos & Riscos":    page_assets_risks,
        "🚨 Incidentes":          page_incidents,
        "📄 Proteção de Dados":   page_privacy,
        "🔍 Auditorias":          page_audits,
        "🎓 Treinamentos":        page_trainings,
        "🤖 Detecção Automática": page_detect_autonomous,
        "⚙️ Administração":       page_admin,
    }
    fn = page_map.get(choice)
    if fn:
        fn()

if __name__ == "__main__":
    main()
