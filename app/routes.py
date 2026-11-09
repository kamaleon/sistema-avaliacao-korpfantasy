"""
Módulo de Rotas e Controladores da API REST.
Gerencia requisições HTTP, autenticação, autorização por perfil (RBAC) e respostas JSON.
"""

import json
import re
from typing import Dict, Any, Tuple, Optional, List
from datetime import datetime

from app.database import get_db_connection, get_brasilia_now_iso
from app.auth import (
    verify_password,
    hash_password,
    create_access_token,
    verify_access_token,
    create_user_session,
    get_user_session,
    update_user_session_activity,
    invalidate_user_session,
    validate_session,
    INACTIVITY_TIMEOUT_SECONDS,
    INACTIVITY_WARNING_SECONDS,
    MAX_SESSION_LIFETIME_SECONDS
)
from app.services import (
    get_all_settings,
    get_dashboard_stats,
    calculate_rankings,
    get_judge_voting_screen,
    submit_candidate_evaluation,
    get_detailed_results_by_category,
    delete_category_safe,
    delete_candidate_safe,
    delete_judge_safe,
    update_setting,
    log_audit,
    get_active_campaign_id,
    get_active_campaign,
    change_admin_password
)


def json_response(data: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
    """Constrói uma resposta HTTP no padrão JSON."""
    resp_headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "X-Content-Type-Options": "nosniff"
    }
    if headers:
        resp_headers.update(headers)
    body_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return status, resp_headers, body_bytes


def error_response(message: str, status: int = 400, extra: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, str], bytes]:
    """Constrói uma resposta de erro padronizada."""
    payload = {"success": False, "error": message}
    if extra:
        payload.update(extra)
    return json_response(payload, status=status)


class Request:
    """Encapsula dados da requisição HTTP vindos do WSGI."""
    def __init__(self, environ: Dict[str, Any]):
        self.environ = environ
        self.method = environ.get("REQUEST_METHOD", "GET").upper()
        self.path = environ.get("PATH_INFO", "/")
        self.query_string = environ.get("QUERY_STRING", "")
        self.ip_address = environ.get("REMOTE_ADDR", "127.0.0.1")
        self._body = None
        self._json = None
        self.user = None

    def read_body(self) -> bytes:
        if self._body is None:
            try:
                content_length = int(self.environ.get("CONTENT_LENGTH", 0) or 0)
            except (ValueError, TypeError):
                content_length = 0
            if content_length > 0:
                self._body = self.environ["wsgi.input"].read(content_length)
            else:
                self._body = b""
        return self._body

    @property
    def json(self) -> Dict[str, Any]:
        if self._json is None:
            body = self.read_body()
            if not body:
                self._json = {}
            else:
                try:
                    self._json = json.loads(body.decode("utf-8"))
                except Exception:
                    self._json = {}
        return self._json

    def get_token(self) -> Optional[str]:
        # Tenta obter do header Authorization: Bearer <token>
        auth_header = self.environ.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()

        # Tenta obter de cookie
        cookie_header = self.environ.get("HTTP_COOKIE", "")
        if cookie_header:
            cookies = [c.strip() for c in cookie_header.split(";")]
            for cookie in cookies:
                if cookie.startswith("auth_token="):
                    return cookie.split("=", 1)[1].strip()

        return None


class Router:
    """Roteador para mapear padrões de URL e métodos a controladores."""
    def __init__(self):
        self.routes = []

    def add(self, method: str, pattern: str, handler):
        # Transforma /api/admin/candidates/<id> em regex
        regex_pattern = "^" + re.sub(r"<int:(\w+)>", r"(?P<\1>\\d+)", pattern) + "$"
        regex = re.compile(regex_pattern)
        self.routes.append((method.upper(), regex, handler))

    def dispatch(self, req: Request) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        for method, regex, handler in self.routes:
            if method == req.method:
                match = regex.match(req.path)
                if match:
                    kwargs = {k: int(v) if v.isdigit() else v for k, v in match.groupdict().items()}
                    return handler(req, **kwargs)
        return None


router = Router()


# ==========================================
# Helpers de Autenticação e Autorização
# ==========================================

def authenticate(req: Request) -> Optional[Dict[str, Any]]:
    token = req.get_token()
    if not token:
        req.auth_error = "MISSING_TOKEN"
        return None
    user_payload = verify_access_token(token)
    if not user_payload:
        req.auth_error = "INVALID_OR_EXPIRED_TOKEN"
        return None

    # Validar sessão com inatividade e duração máxima no banco de dados
    session_id = user_payload.get("sid")
    if session_id:
        conn = get_db_connection()
        try:
            is_bg_poll = req.environ.get("HTTP_X_BACKGROUND_POLL") == "1"
            is_valid, err_code, session_info = validate_session(conn, session_id, is_background_poll=is_bg_poll)
            if not is_valid:
                req.auth_error = err_code
                return None
            req.session_info = session_info
        finally:
            conn.close()

    req.user = user_payload
    return user_payload


def require_role(req: Request, allowed_roles: List[str]) -> Optional[Tuple[int, Dict[str, str], bytes]]:
    user = authenticate(req)
    if not user:
        err = getattr(req, "auth_error", "")
        if err == "INACTIVITY_TIMEOUT":
            return error_response("Sessão encerrada por inatividade (15 minutos sem interação).", status=401, extra={"reason": "INACTIVITY_TIMEOUT"})
        elif err == "MAX_LIFETIME_EXCEEDED":
            return error_response("Sessão expirada: limite máximo de 8 horas atingido. Faça login novamente.", status=401, extra={"reason": "MAX_LIFETIME_EXCEEDED"})
        return error_response("Não autenticado. Forneça credenciais válidas.", status=401, extra={"reason": err or "UNAUTHORIZED"})
    if user.get("role") not in allowed_roles:
        return error_response(
            "Acesso negado: seu perfil não possui permissão para acessar este recurso.",
            status=403
        )
    return None


# ==========================================
# Rotas de Autenticação e Sessão
# ==========================================

def handle_login(req: Request):
    data = req.json
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return error_response("E-mail e senha são obrigatórios.", status=400)

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, password_hash, role, active FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user or not user["active"]:
            return error_response("Credenciais inválidas ou usuário inativo.", status=401)

        if not verify_password(password, user["password_hash"]):
            return error_response("Credenciais inválidas ou usuário inativo.", status=401)

        # Criar sessão com timestamp de inatividade e expiração máxima
        user_agent = req.environ.get("HTTP_USER_AGENT", "")
        session_id = create_user_session(conn, user["id"], ip_address=req.ip_address, user_agent=user_agent)
        token = create_access_token(user["id"], user["role"], user["name"], user["email"], session_id=session_id)
        log_audit(conn, user["id"], user["name"], "LOGIN", f"Login realizado com sucesso ({user['role']})", req.ip_address)

        cookie_header = f"auth_token={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={MAX_SESSION_LIFETIME_SECONDS}"
        return json_response({
            "success": True,
            "token": token,
            "session_id": session_id,
            "session_limits": {
                "inactivity_warning_seconds": INACTIVITY_WARNING_SECONDS,
                "inactivity_timeout_seconds": INACTIVITY_TIMEOUT_SECONDS,
                "max_lifetime_seconds": MAX_SESSION_LIFETIME_SECONDS
            },
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }
        }, headers={"Set-Cookie": cookie_header})
    finally:
        conn.close()

router.add("POST", "/api/auth/login", handle_login)


def handle_refresh_session(req: Request):
    """Renova o tempo de inatividade da sessão ativa."""
    user = authenticate(req)
    if not user:
        err = getattr(req, "auth_error", "")
        if err == "MAX_LIFETIME_EXCEEDED":
            return error_response("Sessão expirada: limite máximo de 8 horas atingido. Faça login novamente.", status=401, extra={"reason": "MAX_LIFETIME_EXCEEDED"})
        return error_response("Sessão inválida ou expirada por inatividade.", status=401, extra={"reason": err or "INVALID_SESSION"})

    session_id = user.get("sid")
    if not session_id:
        return json_response({
            "success": True,
            "message": "Sessão renovada.",
            "inactivity_timeout_seconds": INACTIVITY_TIMEOUT_SECONDS,
            "inactivity_remaining_seconds": INACTIVITY_TIMEOUT_SECONDS
        })

    conn = get_db_connection()
    try:
        import time as _time
        now = int(_time.time())
        session = get_user_session(conn, session_id)
        if not session or not session.get("is_active"):
            return error_response("Sessão não encontrada ou já encerrada.", status=401)

        created_at = int(session["created_at"])
        if (now - created_at) > MAX_SESSION_LIFETIME_SECONDS:
            invalidate_user_session(conn, session_id)
            return error_response("Sessão expirada: limite máximo de 8 horas atingido.", status=401, extra={"reason": "MAX_LIFETIME_EXCEEDED"})

        update_user_session_activity(conn, session_id, now)
        remaining_max = max(0, MAX_SESSION_LIFETIME_SECONDS - (now - created_at))

        return json_response({
            "success": True,
            "message": "Sessão renovada com sucesso.",
            "inactivity_timeout_seconds": INACTIVITY_TIMEOUT_SECONDS,
            "inactivity_remaining_seconds": INACTIVITY_TIMEOUT_SECONDS,
            "max_lifetime_remaining_seconds": remaining_max
        })
    finally:
        conn.close()

router.add("POST", "/api/auth/refresh", handle_refresh_session)


def handle_session_status(req: Request):
    """Consulta os tempos restantes da sessão sem renovar inatividade."""
    req.environ["HTTP_X_BACKGROUND_POLL"] = "1"
    user = authenticate(req)
    if not user:
        err = getattr(req, "auth_error", "")
        return error_response("Sessão inativa ou expirada.", status=401, extra={"reason": err or "SESSION_EXPIRED"})

    session_id = user.get("sid")
    if not session_id:
        return json_response({"success": True, "active": True})

    conn = get_db_connection()
    try:
        import time as _time
        now = int(_time.time())
        session = get_user_session(conn, session_id)
        if not session or not session.get("is_active"):
            return error_response("Sessão inativa.", status=401, extra={"reason": "INACTIVE"})

        created_at = int(session["created_at"])
        last_activity = int(session["last_activity"])

        inactivity_remaining = max(0, INACTIVITY_TIMEOUT_SECONDS - (now - last_activity))
        max_remaining = max(0, MAX_SESSION_LIFETIME_SECONDS - (now - created_at))

        return json_response({
            "success": True,
            "active": True,
            "inactivity_remaining_seconds": inactivity_remaining,
            "max_lifetime_remaining_seconds": max_remaining
        })
    finally:
        conn.close()

router.add("GET", "/api/auth/session-status", handle_session_status)


def handle_get_me(req: Request):
    user = authenticate(req)
    if not user:
        return error_response("Não autenticado.", status=401)

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, role, active FROM users WHERE id = ?", (user["sub"],))
        db_user = cursor.fetchone()
        if not db_user or not db_user["active"]:
            return error_response("Usuário inexistente ou inativo.", status=401)
        return json_response({
            "success": True,
            "user": dict(db_user)
        })
    finally:
        conn.close()

router.add("GET", "/api/auth/me", handle_get_me)


def handle_logout(req: Request):
    token = req.get_token()
    if token:
        user_payload = verify_access_token(token)
        if user_payload and user_payload.get("sid"):
            conn = get_db_connection()
            try:
                invalidate_user_session(conn, user_payload["sid"])
                log_audit(conn, user_payload.get("sub"), user_payload.get("name"), "LOGOUT", "Logout realizado com encerramento de sessão", req.ip_address)
            finally:
                conn.close()

    cookie_header = "auth_token=; Path=/; HttpOnly; Max-Age=0"
    return json_response({"success": True, "message": "Sessão encerrada com sucesso."}, headers={"Set-Cookie": cookie_header})

router.add("POST", "/api/auth/logout", handle_logout)


def handle_admin_security_password(req: Request):
    """Permite ao Administrador Geral alterar sua própria senha de acesso com validações seguras."""
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json
    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))
    confirm_password = str(data.get("confirm_password", ""))

    admin_id = req.user["sub"]
    conn = get_db_connection()
    try:
        success, message = change_admin_password(
            conn,
            admin_id=admin_id,
            current_pwd=current_password,
            new_pwd=new_password,
            confirm_pwd=confirm_password,
            ip_address=req.ip_address
        )
        if not success:
            return error_response(message, status=400)
        return json_response({"success": True, "message": message})
    finally:
        conn.close()

router.add("POST", "/api/admin/security/password", handle_admin_security_password)
router.add("POST", "/api/admin/change-password", handle_admin_security_password)



# ==========================================
# Rotas Públicas
# ==========================================

def handle_public_info(req: Request):
    conn = get_db_connection()
    try:
        settings = get_all_settings(conn)
        return json_response({
            "success": True,
            "event_name": settings.get("event_name", "Sistema de Avaliação"),
            "voting_status": settings.get("voting_status", "OPEN"),
            "public_results_published": settings.get("public_results_published", "false").lower() == "true"
        })
    finally:
        conn.close()

router.add("GET", "/api/public/info", handle_public_info)


def handle_public_results(req: Request):
    conn = get_db_connection()
    try:
        settings = get_all_settings(conn)
        published = settings.get("public_results_published", "false").lower() == "true"
        if not published:
            return error_response(
                "Os resultados oficiais ainda não foram liberados pela organização do evento.",
                status=403,
                extra={"is_published": False}
            )

        rankings_data = calculate_rankings(conn)
        return json_response({
            "success": True,
            "published": True,
            "rankings": rankings_data["rankings"],
            "winners": rankings_data["winners"],
            "is_winner_tie": rankings_data["is_winner_tie"],
            "event_name": settings.get("event_name", "Sistema de Avaliação")
        })
    finally:
        conn.close()

router.add("GET", "/api/public/results", handle_public_results)


# ==========================================
# Rotas do Juiz (Exclusivas)
# ==========================================

def handle_judge_voting_screen(req: Request):
    auth_err = require_role(req, ["JUDGE"])
    if auth_err:
        return auth_err

    judge_id = req.user["sub"]
    conn = get_db_connection()
    try:
        data = get_judge_voting_screen(conn, judge_id)
        return json_response({"success": True, **data})
    finally:
        conn.close()

router.add("GET", "/api/judge/voting", handle_judge_voting_screen)


def handle_judge_vote_submission(req: Request):
    auth_err = require_role(req, ["JUDGE"])
    if auth_err:
        return auth_err

    judge_id = req.user["sub"]
    judge_name = req.user.get("name", "Juiz")
    body = req.json

    candidate_id = body.get("candidate_id")
    scores = body.get("scores")

    if not candidate_id or not isinstance(scores, dict):
        return error_response("Dados de avaliação incompletos: informe 'candidate_id' e o mapa de notas 'scores'.", status=400)

    try:
        candidate_id = int(candidate_id)
    except (ValueError, TypeError):
        return error_response("ID do candidato inválido.", status=400)

    conn = get_db_connection()
    try:
        result = submit_candidate_evaluation(
            conn=conn,
            judge_id=judge_id,
            judge_name=judge_name,
            candidate_id=candidate_id,
            scores=scores,
            ip_address=req.ip_address
        )
        return json_response(result)
    except ValueError as e:
        return error_response(str(e), status=400)
    finally:
        conn.close()

router.add("POST", "/api/judge/vote", handle_judge_vote_submission)


# ==========================================
# Rotas do Administrador (Exclusivas)
# ==========================================

def handle_admin_dashboard(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        stats = get_dashboard_stats(conn)
        rankings_data = calculate_rankings(conn)
        return json_response({
            "success": True,
            "stats": stats,
            "winners": rankings_data["winners"],
            "is_winner_tie": rankings_data["is_winner_tie"],
            "rankings": rankings_data["rankings"]
        })
    finally:
        conn.close()

router.add("GET", "/api/admin/dashboard", handle_admin_dashboard)


def handle_admin_rankings(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        rankings_data = calculate_rankings(conn)
        return json_response({"success": True, **rankings_data})
    finally:
        conn.close()

router.add("GET", "/api/admin/rankings", handle_admin_rankings)


def handle_admin_matrix(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        matrix_data = get_detailed_results_by_category(conn)
        return json_response({"success": True, **matrix_data})
    finally:
        conn.close()

router.add("GET", "/api/admin/matrix", handle_admin_matrix)


def handle_admin_settings_get(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        settings = get_all_settings(conn)
        return json_response({"success": True, "settings": settings})
    finally:
        conn.close()

router.add("GET", "/api/admin/settings", handle_admin_settings_get)


def handle_admin_settings_update(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    body = req.json
    allowed_keys = [
        "event_name",
        "voting_status",
        "allow_corrections",
        "public_results_published",
        "show_provisional_winner"
    ]

    conn = get_db_connection()
    try:
        for k, v in body.items():
            if k in allowed_keys:
                if k == "voting_status" and v not in ("OPEN", "CLOSED", "PAUSED"):
                    return error_response("Status de votação deve ser 'OPEN', 'CLOSED' ou 'PAUSED'.", status=400)
                update_setting(conn, k, str(v), req.user["sub"], req.user.get("name"))

        settings = get_all_settings(conn)
        return json_response({"success": True, "settings": settings, "message": "Configurações atualizadas com sucesso."})
    finally:
        conn.close()

router.add("PUT", "/api/admin/settings", handle_admin_settings_update)


# --- CRUD Candidatos ---

# --- CRUD Candidatos ---

def handle_admin_candidates_list(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        active_camp_id = get_active_campaign_id(conn)
        active_camp = get_active_campaign(conn)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, name, number, photo_url, description, active, campaign_id, created_at 
            FROM candidates 
            WHERE campaign_id = ?
            ORDER BY CAST(number AS INTEGER) ASC, id ASC
        """, (active_camp_id,))
        candidates = [dict(row) for row in cursor.fetchall()]
        return json_response({
            "success": True, 
            "candidates": candidates,
            "active_campaign": active_camp
        })
    finally:
        conn.close()

router.add("GET", "/api/admin/candidates", handle_admin_candidates_list)


def handle_admin_candidates_create(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json or {}
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()

    if not name:
        return error_response("O nome do candidato é obrigatório.", status=400)

    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            campaign_id = get_active_campaign_id(conn)
            cursor = conn.cursor()
            # Próximo número sequencial dentro da campanha atual
            cursor.execute("SELECT COALESCE(MAX(CAST(number AS INTEGER)), 0) + 1 FROM candidates WHERE campaign_id = ?", (campaign_id,))
            next_num = cursor.fetchone()[0]
            number = f"{next_num:02d}"

            cursor.execute("""
                INSERT INTO candidates (name, number, photo_url, description, active, campaign_id, created_at, updated_at)
                VALUES (?, ?, '', ?, 1, ?, ?, ?)
            """, (name, number, description, campaign_id, now, now))
            new_id = cursor.lastrowid
            log_audit(
                conn, 
                req.user["sub"], 
                req.user.get("name"), 
                "CREATE_CANDIDATE", 
                f"Candidato '{name}' (Nº {number}, ID {new_id}) cadastrado na campanha ID {campaign_id}.", 
                req.ip_address
            )

        return json_response({
            "success": True, 
            "id": new_id, 
            "number": number, 
            "message": "Candidato cadastrado com sucesso."
        }, status=201)
    finally:
        conn.close()

router.add("POST", "/api/admin/candidates", handle_admin_candidates_create)


def handle_admin_candidates_bulk_import(req: Request):
    """
    Importação de candidatos em lote via texto/arquivo txt.
    Cada linha não-vazia representa um candidato.
    O número de inscrição é atribuído sequencialmente.
    """
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json or {}
    raw_names = data.get("names")
    if raw_names is None:
        raw_text = data.get("text") or data.get("content") or ""
        raw_names = raw_text.splitlines()

    if not isinstance(raw_names, list):
        return error_response("Formato inválido. Envie um arquivo txt ou lista de nomes.", status=400)

    names = [str(n).strip() for n in raw_names if str(n).strip()]

    if not names:
        return error_response("Nenhum nome de candidato válido foi informado no arquivo.", status=400)

    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            campaign_id = get_active_campaign_id(conn)
            cursor = conn.cursor()
            cursor.execute("SELECT COALESCE(MAX(CAST(number AS INTEGER)), 0) + 1 FROM candidates WHERE campaign_id = ?", (campaign_id,))
            next_num = cursor.fetchone()[0]

            inserted = []
            for name in names:
                number = f"{next_num:02d}"
                cursor.execute("""
                    INSERT INTO candidates (name, number, photo_url, description, active, campaign_id, created_at, updated_at)
                    VALUES (?, ?, '', '', 1, ?, ?, ?)
                """, (name, number, campaign_id, now, now))
                inserted.append({"id": cursor.lastrowid, "name": name, "number": number})
                next_num += 1

            log_audit(
                conn, 
                req.user["sub"], 
                req.user.get("name"), 
                "BULK_IMPORT_CANDIDATES", 
                f"Importação em lote de {len(inserted)} candidatos na campanha ID {campaign_id}.", 
                req.ip_address
            )

        return json_response({
            "success": True,
            "count": len(inserted),
            "candidates": inserted,
            "message": f"{len(inserted)} candidato(s) importado(s) com sucesso com números sequenciais atribuídos!"
        }, status=201)
    finally:
        conn.close()

router.add("POST", "/api/admin/candidates/bulk-import", handle_admin_candidates_bulk_import)


def handle_admin_candidates_clear_campaign(req: Request):
    """
    Exclui todos os candidatos e todas as avaliações associadas da campanha ativa atual.
    """
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        with conn:
            campaign_id = get_active_campaign_id(conn)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM candidates WHERE campaign_id = ?", (campaign_id,))
            candidate_ids = [row[0] for row in cursor.fetchall()]
            count = len(candidate_ids)

            if count > 0:
                placeholders = ",".join("?" * count)
                conn.execute(f"DELETE FROM evaluations WHERE candidate_id IN ({placeholders})", candidate_ids)
                conn.execute(f"DELETE FROM candidate_submissions WHERE candidate_id IN ({placeholders})", candidate_ids)
                conn.execute("DELETE FROM candidates WHERE campaign_id = ?", (campaign_id,))

            log_audit(
                conn,
                req.user["sub"],
                req.user.get("name"),
                "CLEAR_CAMPAIGN_CANDIDATES",
                f"Exclusão em massa: {count} candidatos e todas as avaliações da campanha ID {campaign_id} foram removidos.",
                req.ip_address
            )

        return json_response({
            "success": True,
            "deleted_count": count,
            "message": f"Todos os {count} candidatos e notas da campanha atual foram removidos com sucesso."
        })
    finally:
        conn.close()

router.add("DELETE", "/api/admin/candidates/clear-current-campaign", handle_admin_candidates_clear_campaign)
router.add("DELETE", "/api/admin/candidates/clear-all", handle_admin_candidates_clear_campaign)


def handle_admin_candidates_update(req: Request, candidate_id: int):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json or {}
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()
    active = int(data.get("active", 1))

    if not name:
        return error_response("O nome do candidato é obrigatório.", status=400)

    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            # Nota: O número de inscrição não é alterado (imutável)
            cursor.execute("""
                UPDATE candidates
                SET name = ?, description = ?, active = ?, updated_at = ?
                WHERE id = ?
            """, (name, description, active, now, candidate_id))
            if cursor.rowcount == 0:
                return error_response("Candidato não encontrado.", status=404)
            log_audit(conn, req.user["sub"], req.user.get("name"), "UPDATE_CANDIDATE", f"Candidato ID {candidate_id} atualizado.", req.ip_address)

        return json_response({"success": True, "message": "Candidato atualizado com sucesso."})
    finally:
        conn.close()

router.add("PUT", "/api/admin/candidates/<int:candidate_id>", handle_admin_candidates_update)


def handle_admin_candidates_delete(req: Request, candidate_id: int):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        success, msg = delete_candidate_safe(conn, candidate_id, req.user["sub"], req.user.get("name", "Admin"))
        if not success:
            return error_response(msg, status=400)
        return json_response({"success": True, "message": msg})
    finally:
        conn.close()

router.add("DELETE", "/api/admin/candidates/<int:candidate_id>", handle_admin_candidates_delete)


# --- Gerenciamento de Campanhas de Votação ---

def handle_admin_campaigns_list(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        active_camp_id = get_active_campaign_id(conn)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.id, c.name, c.description, c.status, c.created_at,
                   (SELECT COUNT(*) FROM candidates cand WHERE cand.campaign_id = c.id) as candidates_count
            FROM campaigns c
            ORDER BY c.id DESC
        """)
        campaigns = [dict(row) for row in cursor.fetchall()]
        return json_response({
            "success": True,
            "active_campaign_id": active_camp_id,
            "campaigns": campaigns
        })
    finally:
        conn.close()

router.add("GET", "/api/admin/campaigns", handle_admin_campaigns_list)


def handle_admin_campaigns_create(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json or {}
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()

    if not name:
        return error_response("O nome da campanha é obrigatório.", status=400)

    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO campaigns (name, description, status, created_at, updated_at)
                VALUES (?, ?, 'ACTIVE', ?, ?)
            """, (name, description, now, now))
            new_id = cursor.lastrowid

            # Definir imediatamente como campanha ativa
            update_setting(conn, "active_campaign_id", str(new_id), req.user["sub"], req.user.get("name"))

            log_audit(
                conn,
                req.user["sub"],
                req.user.get("name"),
                "CREATE_CAMPAIGN",
                f"Nova campanha '{name}' (ID {new_id}) criada e ativada. Votação iniciada do zero.",
                req.ip_address
            )

        return json_response({
            "success": True,
            "id": new_id,
            "name": name,
            "message": f"Nova campanha '{name}' criada e ativada com sucesso! As votações agora iniciam do zero para esta campanha."
        }, status=201)
    finally:
        conn.close()

router.add("POST", "/api/admin/campaigns", handle_admin_campaigns_create)


def handle_admin_campaigns_activate(req: Request, campaign_id: int):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM campaigns WHERE id = ?", (campaign_id,))
        camp = cursor.fetchone()
        if not camp:
            return error_response("Campanha não encontrada.", status=404)

        camp_name = camp["name"]
        with conn:
            update_setting(conn, "active_campaign_id", str(campaign_id), req.user["sub"], req.user.get("name"))
            log_audit(
                conn,
                req.user["sub"],
                req.user.get("name"),
                "ACTIVATE_CAMPAIGN",
                f"Campanha '{camp_name}' (ID {campaign_id}) definida como ativa.",
                req.ip_address
            )

        return json_response({
            "success": True,
            "active_campaign_id": campaign_id,
            "message": f"Campanha '{camp_name}' agora é a campanha ativa."
        })
    finally:
        conn.close()

router.add("POST", "/api/admin/campaigns/<int:campaign_id>/activate", handle_admin_campaigns_activate)


# --- CRUD Juízes ---

def handle_admin_judges_list(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, active, created_at FROM users WHERE role = 'JUDGE' ORDER BY id DESC")
        judges = [dict(row) for row in cursor.fetchall()]
        return json_response({"success": True, "judges": judges})
    finally:
        conn.close()

router.add("GET", "/api/admin/judges", handle_admin_judges_list)


def handle_admin_judges_create(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()

    if not name or not email or not password:
        return error_response("Nome, e-mail e senha são obrigatórios.", status=400)

    pwd_hash = hash_password(password)
    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                return error_response("Este e-mail já está cadastrado no sistema.", status=400)

            cursor.execute("""
                INSERT INTO users (name, email, password_hash, role, active, created_at, updated_at)
                VALUES (?, ?, ?, 'JUDGE', 1, ?, ?)
            """, (name, email, pwd_hash, now, now))
            new_id = cursor.lastrowid
            log_audit(conn, req.user["sub"], req.user.get("name"), "CREATE_JUDGE", f"Juiz '{name}' (ID {new_id}, email {email}) cadastrado.", req.ip_address)

        return json_response({"success": True, "id": new_id, "message": "Juiz cadastrado com sucesso."}, status=201)
    finally:
        conn.close()

router.add("POST", "/api/admin/judges", handle_admin_judges_create)


def handle_admin_judges_update(req: Request, judge_id: int):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", "")).strip()
    active = int(data.get("active", 1))

    if not name or not email:
        return error_response("Nome e e-mail são obrigatórios.", status=400)

    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, judge_id))
            if cursor.fetchone():
                return error_response("Já existe outro usuário utilizando este e-mail.", status=400)

            if password:
                pwd_hash = hash_password(password)
                cursor.execute("""
                    UPDATE users
                    SET name = ?, email = ?, password_hash = ?, active = ?, updated_at = ?
                    WHERE id = ? AND role = 'JUDGE'
                """, (name, email, pwd_hash, active, now, judge_id))
            else:
                cursor.execute("""
                    UPDATE users
                    SET name = ?, email = ?, active = ?, updated_at = ?
                    WHERE id = ? AND role = 'JUDGE'
                """, (name, email, active, now, judge_id))

            if cursor.rowcount == 0:
                return error_response("Juiz não encontrado.", status=404)
            log_audit(conn, req.user["sub"], req.user.get("name"), "UPDATE_JUDGE", f"Juiz ID {judge_id} atualizado.", req.ip_address)

        return json_response({"success": True, "message": "Juiz atualizado com sucesso."})
    finally:
        conn.close()

router.add("PUT", "/api/admin/judges/<int:judge_id>", handle_admin_judges_update)


def handle_admin_judges_reset_password(req: Request, judge_id: int):
    """Permite ao administrador redefinir a senha de qualquer juiz cadastrado."""
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json or {}
    new_password = str(data.get("password", "")).strip()

    if not new_password:
        return error_response("Informe a nova senha para o juiz.", status=400)

    if len(new_password) < 4:
        return error_response("A senha deve ter no mínimo 4 caracteres.", status=400)

    pwd_hash = hash_password(new_password)
    now = get_brasilia_now_iso()

    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, email FROM users WHERE id = ? AND role = 'JUDGE'", (judge_id,))
            judge = cursor.fetchone()
            if not judge:
                return error_response("Juiz não encontrado.", status=404)

            cursor.execute("""
                UPDATE users
                SET password_hash = ?, updated_at = ?
                WHERE id = ? AND role = 'JUDGE'
            """, (pwd_hash, now, judge_id))

            log_audit(
                conn,
                req.user["sub"],
                req.user.get("name"),
                "RESET_JUDGE_PASSWORD",
                f"Senha do juiz '{judge['name']}' (ID {judge_id}, email {judge['email']}) foi redefinida pelo administrador.",
                req.ip_address
            )

        return json_response({
            "success": True,
            "message": f"Senha do juiz '{judge['name']}' redefinida com sucesso."
        })
    finally:
        conn.close()

router.add("POST", "/api/admin/judges/<int:judge_id>/reset-password", handle_admin_judges_reset_password)


def handle_admin_judges_delete(req: Request, judge_id: int):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        success, msg = delete_judge_safe(conn, judge_id, req.user["sub"], req.user.get("name", "Admin"))
        if not success:
            return error_response(msg, status=400)
        return json_response({"success": True, "message": msg})
    finally:
        conn.close()

router.add("DELETE", "/api/admin/judges/<int:judge_id>", handle_admin_judges_delete)


# --- CRUD Categorias ---

def handle_admin_categories_list(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, description, weight, display_order, active, created_at FROM categories ORDER BY display_order ASC, id ASC")
        categories = [dict(row) for row in cursor.fetchall()]
        return json_response({"success": True, "categories": categories})
    finally:
        conn.close()

router.add("GET", "/api/admin/categories", handle_admin_categories_list)


def handle_admin_categories_create(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()
    display_order = int(data.get("display_order", 0) or 0)

    if not name:
        return error_response("O nome da categoria é obrigatório.", status=400)

    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO categories (name, description, weight, display_order, active, created_at, updated_at)
                VALUES (?, ?, 1.0, ?, 1, ?, ?)
            """, (name, description, display_order, now, now))
            new_id = cursor.lastrowid
            log_audit(conn, req.user["sub"], req.user.get("name"), "CREATE_CATEGORY", f"Categoria '{name}' (ID {new_id}) criada.", req.ip_address)

        return json_response({"success": True, "id": new_id, "message": "Categoria criada com sucesso."}, status=201)
    finally:
        conn.close()

router.add("POST", "/api/admin/categories", handle_admin_categories_create)


def handle_admin_categories_update(req: Request, category_id: int):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    data = req.json
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()
    display_order = int(data.get("display_order", 0) or 0)
    active = int(data.get("active", 1))

    if not name:
        return error_response("O nome da categoria é obrigatório.", status=400)

    now = get_brasilia_now_iso()
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE categories
                SET name = ?, description = ?, display_order = ?, active = ?, updated_at = ?
                WHERE id = ?
            """, (name, description, display_order, active, now, category_id))
            if cursor.rowcount == 0:
                return error_response("Categoria não encontrada.", status=404)
            log_audit(conn, req.user["sub"], req.user.get("name"), "UPDATE_CATEGORY", f"Categoria ID {category_id} ('{name}') atualizada.", req.ip_address)

        return json_response({"success": True, "message": "Categoria atualizada com sucesso."})
    finally:
        conn.close()

router.add("PUT", "/api/admin/categories/<int:category_id>", handle_admin_categories_update)


def handle_admin_categories_delete(req: Request, category_id: int):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        success, msg = delete_category_safe(conn, category_id, req.user["sub"], req.user.get("name", "Admin"))
        if not success:
            return error_response(msg, status=400)
        return json_response({"success": True, "message": msg})
    finally:
        conn.close()

router.add("DELETE", "/api/admin/categories/<int:category_id>", handle_admin_categories_delete)


# --- Logs de Auditoria ---

def handle_admin_audit_logs(req: Request):
    auth_err = require_role(req, ["ADMIN"])
    if auth_err:
        return auth_err

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, user_id, user_name, action, details, ip_address, created_at FROM audit_logs ORDER BY id DESC LIMIT 100")
        logs = [dict(row) for row in cursor.fetchall()]
        return json_response({"success": True, "logs": logs})
    finally:
        conn.close()

router.add("GET", "/api/admin/audit-logs", handle_admin_audit_logs)
