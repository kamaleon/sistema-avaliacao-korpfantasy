"""
Suíte de Testes Automatizados.
Garante a integridade das regras de negócio, autenticação, permissões RBAC, cálculos matemáticos,
prevenção de duplicidade, tratamento de empates e persistência do banco de dados.
"""

import unittest
import os
import sys
import json
import io
import tempfile
import sqlite3

# Configurar caminho base
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.database import init_db, seed_default_data, get_db_connection
from app.auth import create_access_token, hash_password
from app.services import (
    calculate_rankings,
    submit_candidate_evaluation,
    delete_category_safe,
    update_setting,
    get_dashboard_stats
)
from app.wsgi import application


class WSGITestClient:
    """Cliente de teste in-memory para chamadas à aplicação WSGI."""
    def __init__(self, app):
        self.app = app

    def request(self, method: str, path: str, body: dict = None, headers: dict = None):
        headers = headers or {}
        environ = {
            "REQUEST_METHOD": method.upper(),
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "REMOTE_ADDR": "127.0.0.1",
            "wsgi.url_scheme": "http",
        }

        body_bytes = b""
        if body is not None:
            body_bytes = json.dumps(body).encode("utf-8")
            environ["CONTENT_TYPE"] = "application/json"
            environ["CONTENT_LENGTH"] = str(len(body_bytes))

        environ["wsgi.input"] = io.BytesIO(body_bytes)

        for k, v in headers.items():
            k_upper = k.upper().replace("-", "_")
            if k_upper in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                environ[k_upper] = v
            else:
                environ[f"HTTP_{k_upper}"] = v

        status_code = None
        response_headers = {}

        def start_response(status, resp_headers, exc_info=None):
            nonlocal status_code, response_headers
            status_code = int(status.split()[0])
            response_headers = dict(resp_headers)

        result_iterable = self.app(environ, start_response)
        response_data = b"".join(result_iterable)

        try:
            json_data = json.loads(response_data.decode("utf-8"))
        except Exception:
            json_data = None

        return status_code, response_headers, json_data, response_data

    def get(self, path: str, headers: dict = None):
        return self.request("GET", path, headers=headers)

    def post(self, path: str, body: dict = None, headers: dict = None):
        return self.request("POST", path, body=body, headers=headers)

    def put(self, path: str, body: dict = None, headers: dict = None):
        return self.request("PUT", path, body=body, headers=headers)

    def delete(self, path: str, headers: dict = None):
        return self.request("DELETE", path, headers=headers)


class TestCandidateEvaluationSystem(unittest.TestCase):
    """Casos de teste do Sistema de Avaliação."""

    def setUp(self):
        # Criar banco de dados temporário para isolamento dos testes
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.environ["DATABASE_PATH"] = self.temp_db_path

        init_db(self.temp_db_path)
        seed_default_data(self.temp_db_path, force=True)

        self.client = WSGITestClient(application)

        # Tokens de teste
        self.admin_token = create_access_token(1, "ADMIN", "Administrador Geral", "admin@sistema.com")
        self.judge_token = create_access_token(2, "JUDGE", "Dra. Helena Martins", "helena@sistema.com")
        self.judge2_token = create_access_token(3, "JUDGE", "Prof. Carlos Eduardo", "carlos@sistema.com")

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    # -------------------------------------------------------------------------
    # 1. Segurança e RBAC: Juiz não pode acessar rotas de Administrador
    # -------------------------------------------------------------------------
    def test_judge_cannot_access_admin_endpoints(self):
        """Garante que um usuário com perfil JUDGE receba 403 Forbidden ao acessar rotas administrativas."""
        headers = {"Authorization": f"Bearer {self.judge_token}"}

        admin_routes = [
            ("GET", "/api/admin/dashboard"),
            ("GET", "/api/admin/rankings"),
            ("GET", "/api/admin/candidates"),
            ("POST", "/api/admin/candidates"),
            ("GET", "/api/admin/judges"),
            ("GET", "/api/admin/categories"),
            ("GET", "/api/admin/settings"),
            ("PUT", "/api/admin/settings"),
        ]

        for method, route in admin_routes:
            status, _, data, _ = self.client.request(method, route, headers=headers)
            self.assertEqual(
                status, 403,
                f"Juiz conseguiu acessar {method} {route} com status {status}! Esperado 403."
            )
            self.assertFalse(data.get("success"))

    def test_admin_can_access_admin_endpoints(self):
        """Garante que o Administrador acesse normalmente as rotas administrativas."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        status, _, data, _ = self.client.get("/api/admin/dashboard", headers=headers)
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))

    # -------------------------------------------------------------------------
    # 2. Validação de Notas: Apenas inteiros de 1 a 10 são aceitos
    # -------------------------------------------------------------------------
    def test_reject_scores_outside_range(self):
        """Garante que notas menores que 1, maiores que 10 ou inválidas sejam rejeitadas."""
        headers = {"Authorization": f"Bearer {self.judge_token}"}

        # Obter IDs das categorias ativas
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1")
        cats = [r["id"] for r in cur.fetchall()]
        conn.close()

        invalid_scores = [
            0,     # Abaixo de 1
            11,    # Acima de 10
            -1,    # Negativo
            100,   # Muito alto
            "abc"  # Não numérico
        ]

        for inv in invalid_scores:
            scores = {str(c): 8 for c in cats}
            scores[str(cats[0])] = inv  # Uma nota inválida

            status, _, data, _ = self.client.post("/api/judge/vote", body={
                "candidate_id": 1,
                "scores": scores
            }, headers=headers)

            self.assertEqual(status, 400, f"Nota inválida {inv} foi aceita com status {status}!")
            self.assertFalse(data.get("success"))

    # -------------------------------------------------------------------------
    # 3. Unicidade e Duplicidade: Não duplica registros para o mesmo juiz/candidato/categoria
    # -------------------------------------------------------------------------
    def test_single_vote_per_combination_and_update(self):
        """
        Garante que um juiz não gere registros duplicados no banco de dados para a mesma
        combinação de candidato e categoria. Se correção for permitida, atualiza a nota.
        """
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1")
        cats = [r["id"] for r in cur.fetchall()]
        conn.close()

        headers = {"Authorization": f"Bearer {self.judge_token}"}

        # Primeira avaliação (nota 7 para todas)
        scores_1 = {str(c): 7 for c in cats}
        status, _, data, _ = self.client.post("/api/judge/vote", body={
            "candidate_id": 1,
            "scores": scores_1
        }, headers=headers)
        self.assertEqual(status, 200)

        # Conferir no banco a quantidade de linhas
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM evaluations WHERE judge_id = 2 AND candidate_id = 1")
        count_first = cur.fetchone()[0]
        self.assertEqual(count_first, len(cats))

        # Segunda avaliação com notas alteradas (nota 9)
        scores_2 = {str(c): 9 for c in cats}
        status2, _, data2, _ = self.client.post("/api/judge/vote", body={
            "candidate_id": 1,
            "scores": scores_2
        }, headers=headers)
        self.assertEqual(status2, 200)

        # A contagem de linhas no banco DEVE permanecer exatamente a mesma!
        cur.execute("SELECT COUNT(*) FROM evaluations WHERE judge_id = 2 AND candidate_id = 1")
        count_second = cur.fetchone()[0]
        self.assertEqual(count_second, count_first)

        # O valor da nota deve ter sido atualizado para 9
        cur.execute("SELECT score FROM evaluations WHERE judge_id = 2 AND candidate_id = 1 AND category_id = ?", (cats[0],))
        updated_score = cur.fetchone()[0]
        self.assertEqual(updated_score, 9)
        conn.close()

    # -------------------------------------------------------------------------
    # 4. Bloqueio de Alteração de Notas quando Desabilitado pelo Admin
    # -------------------------------------------------------------------------
    def test_block_correction_when_disabled(self):
        """Garante que o juiz não possa corrigir notas quando a opção estiver desativada."""
        conn = get_db_connection(self.temp_db_path)
        update_setting(conn, "allow_corrections", "false")
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1")
        cats = [r["id"] for r in cur.fetchall()]
        conn.close()

        headers = {"Authorization": f"Bearer {self.judge_token}"}

        # Primeira submissão com sucesso
        scores_1 = {str(c): 8 for c in cats}
        status, _, data, _ = self.client.post("/api/judge/vote", body={
            "candidate_id": 1,
            "scores": scores_1
        }, headers=headers)
        self.assertEqual(status, 200)

        # Tentativa de alteração com correção desabilitada deve falhar
        scores_2 = {str(c): 10 for c in cats}
        status, _, data, _ = self.client.post("/api/judge/vote", body={
            "candidate_id": 1,
            "scores": scores_2
        }, headers=headers)
        self.assertEqual(status, 400)
        self.assertIn("desabilitada", data.get("error", "").lower())

    # -------------------------------------------------------------------------
    # 5. Bloqueio após Encerramento da Votação
    # -------------------------------------------------------------------------
    def test_block_votes_when_voting_closed(self):
        """Garante que nenhuma nota seja aceita se a votação estiver ENCERRADA (CLOSED)."""
        conn = get_db_connection(self.temp_db_path)
        update_setting(conn, "voting_status", "CLOSED")
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1")
        cats = [r["id"] for r in cur.fetchall()]
        conn.close()

        headers = {"Authorization": f"Bearer {self.judge_token}"}
        scores = {str(c): 10 for c in cats}

        status, _, data, _ = self.client.post("/api/judge/vote", body={
            "candidate_id": 1,
            "scores": scores
        }, headers=headers)

        self.assertEqual(status, 400)
        self.assertIn("encerrada", data.get("error", "").lower())

    # -------------------------------------------------------------------------
    # 6. Cálculo Matemático da Média Final e Ordenação
    # -------------------------------------------------------------------------
    def test_calculation_of_final_average(self):
        """
        Fórmula: Média final = soma de todas as notas válidas do candidato ÷ quantidade total de notas válidas
        Exemplo:
          Candidato 1 recebe:
            Juiz A: [8, 9, 10]
            Juiz B: [7, 8, 9]
            Soma = 51, Total = 6 notas
            Média = 51 / 6 = 8.50
        """
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1 ORDER BY id ASC")
        cats = [r["id"] for r in cur.fetchall()][:3]  # Pegar 3 categorias

        # Juiz Helena (id 2) avalia Candidato 1
        submit_candidate_evaluation(conn, 2, "Helena", 1, {cats[0]: 8, cats[1]: 9, cats[2]: 10})
        # Juiz Carlos (id 3) avalia Candidato 1
        submit_candidate_evaluation(conn, 3, "Carlos", 1, {cats[0]: 7, cats[1]: 8, cats[2]: 9})

        rankings_data = calculate_rankings(conn)
        conn.close()

        c1 = next(c for c in rankings_data["rankings"] if c["id"] == 1)
        self.assertEqual(c1["total_scores_count"], 6)
        self.assertEqual(c1["sum_scores"], 51)
        self.assertEqual(c1["final_average"], 8.50)
        self.assertEqual(c1["final_average_formatted"], "8.50")

    # -------------------------------------------------------------------------
    # 7. Identificação de Empates sem Escolha Arbitrária
    # -------------------------------------------------------------------------
    def test_tie_identification_in_rankings(self):
        """
        Se dois candidatos tiverem a mesma média final, ambos devem receber
        o mesmo rank e a flag is_tie deve ser verdadeira.
        """
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1 ORDER BY id ASC")
        cats = [r["id"] for r in cur.fetchall()][:3]

        # Candidato 1 recebe notas com média 9.00
        submit_candidate_evaluation(conn, 2, "Helena", 1, {cats[0]: 9, cats[1]: 9, cats[2]: 9})

        # Candidato 2 recebe notas diferentes que também resultam em média 9.00
        submit_candidate_evaluation(conn, 2, "Helena", 2, {cats[0]: 8, cats[1]: 9, cats[2]: 10})

        # Candidato 3 recebe notas com média 7.00
        submit_candidate_evaluation(conn, 2, "Helena", 3, {cats[0]: 7, cats[1]: 7, cats[2]: 7})

        rankings_data = calculate_rankings(conn)
        conn.close()

        c1 = next(c for c in rankings_data["rankings"] if c["id"] == 1)
        c2 = next(c for c in rankings_data["rankings"] if c["id"] == 2)
        c3 = next(c for c in rankings_data["rankings"] if c["id"] == 3)

        self.assertEqual(c1["final_average"], 9.00)
        self.assertEqual(c2["final_average"], 9.00)

        # Ambos devem compartilhar a 1ª posição!
        self.assertEqual(c1["rank"], 1)
        self.assertEqual(c2["rank"], 1)
        self.assertTrue(c1["is_tie"])
        self.assertTrue(c2["is_tie"])

        # O 3º colocado deve ficar no rank 3 (ou próximo), sem ser escolhido 1º arbitrariamente
        self.assertEqual(c3["rank"], 3)
        self.assertFalse(c3["is_tie"])

        # Ambos os candidatos empatados devem estar na lista de vencedores
        self.assertTrue(rankings_data["is_winner_tie"])
        winner_ids = {w["id"] for w in rankings_data["winners"]}
        self.assertEqual(winner_ids, {1, 2})

    # -------------------------------------------------------------------------
    # 8. Integridade de Categorias: Desativação segura quando há notas
    # -------------------------------------------------------------------------
    def test_safe_category_deletion_preserves_integrity(self):
        """
        Se uma categoria já possuir notas registradas, a exclusão deve
        desativá-la (soft delete) para proteger o histórico, em vez de apagar os votos.
        """
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1 ORDER BY id ASC")
        cat_id = cur.fetchone()["id"]

        # Votar nesta categoria
        submit_candidate_evaluation(conn, 2, "Helena", 1, {cat_id: 10, cat_id+1: 10, cat_id+2: 10})

        # Tentar excluir a categoria
        success, msg = delete_category_safe(conn, cat_id, 1, "Admin")
        self.assertTrue(success)

        # Verificar se a categoria continua no banco, porém com active = 0
        cur.execute("SELECT active FROM categories WHERE id = ?", (cat_id,))
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["active"], 0)

        # E as avaliações permanecem intactas no banco!
        cur.execute("SELECT COUNT(*) FROM evaluations WHERE category_id = ?", (cat_id,))
        eval_count = cur.fetchone()[0]
        self.assertGreater(eval_count, 0)
        conn.close()

    # -------------------------------------------------------------------------
    # 9. Persistência de Dados no SQLite após Reinicialização
    # -------------------------------------------------------------------------
    def test_database_persistence_across_connections(self):
        """Garante que dados gravados continuem presentes após fechar e reabrir conexões."""
        conn1 = get_db_connection(self.temp_db_path)
        submit_candidate_evaluation(conn1, 2, "Helena", 1, {1: 8, 2: 9, 3: 10})
        conn1.close()

        # Simular reinício completo da aplicação abrindo nova conexão
        conn2 = get_db_connection(self.temp_db_path)
        cur = conn2.cursor()
        cur.execute("SELECT score FROM evaluations WHERE judge_id = 2 AND candidate_id = 1 AND category_id = 1")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["score"], 8)
        conn2.close()


    # -------------------------------------------------------------------------
    # 10. Rejeição de Avaliações Incompletas
    # -------------------------------------------------------------------------
    def test_incomplete_evaluations_rejected(self):
        """Garante que a submissão falhe caso alguma das categorias ativas não receba nota."""
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1 ORDER BY id ASC")
        cats = [r["id"] for r in cur.fetchall()]
        conn.close()

        headers = {"Authorization": f"Bearer {self.judge_token}"}
        # Enviar apenas para a primeira categoria, deixando as outras vazias
        incomplete_scores = {str(cats[0]): 9}

        status, _, data, _ = self.client.post("/api/judge/vote", body={
            "candidate_id": 1,
            "scores": incomplete_scores
        }, headers=headers)

        self.assertEqual(status, 400)
        self.assertIn("incompleta", data.get("error", "").lower())

    # -------------------------------------------------------------------------
    # 11. Autenticação e Login
    # -------------------------------------------------------------------------
    def test_login_flow_valid_and_invalid(self):
        """Garante que credenciais válidas retornem token JWT e inválidas sejam rejeitadas com 401."""
        # Válido
        status, _, data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        self.assertIn("token", data)
        self.assertEqual(data["user"]["role"], "ADMIN")

        # Senha incorreta
        status_err, _, data_err, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "senha_errada"
        })
        self.assertEqual(status_err, 401)
        self.assertFalse(data_err.get("success"))

    # -------------------------------------------------------------------------
    # 12. Divulgação Pública de Resultados (Controle de Acesso)
    # -------------------------------------------------------------------------
    def test_public_results_publishing_toggle(self):
        """Resultados públicos devem ser bloqueados com 403 até que o admin autorize a publicação."""
        # 1. Quando não publicado: 403
        status, _, data, _ = self.client.get("/api/public/results")
        self.assertEqual(status, 403)
        self.assertFalse(data.get("success"))

        # 2. Admin publica resultados
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        self.client.put("/api/admin/settings", body={
            "public_results_published": "true"
        }, headers=admin_headers)

        # 3. Agora a consulta pública deve retornar 200 com os dados
        status2, _, data2, _ = self.client.get("/api/public/results")
        self.assertEqual(status2, 200)
        self.assertTrue(data2.get("success"))
        self.assertTrue(data2.get("published"))

    # -------------------------------------------------------------------------
    # 13. CRUD Administrativo Completo de Candidatos
    # -------------------------------------------------------------------------
    def test_candidate_crud(self):
        """Testa criação, listagem, edição e exclusão de candidato pelo Administrador."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Criar
        status, _, data, _ = self.client.post("/api/admin/candidates", body={
            "name": "Novo Candidato Teste",
            "number": "99",
            "description": "Talento especial"
        }, headers=headers)
        self.assertEqual(status, 201)
        cand_id = data["id"]

        # Atualizar
        status_up, _, _, _ = self.client.put(f"/api/admin/candidates/{cand_id}", body={
            "name": "Candidato Teste Atualizado",
            "number": "99B",
            "description": "Nova descrição"
        }, headers=headers)
        self.assertEqual(status_up, 200)

        # Excluir
        status_del, _, data_del, _ = self.client.delete(f"/api/admin/candidates/{cand_id}", headers=headers)
        self.assertEqual(status_del, 200)
        self.assertTrue(data_del.get("success"))

    # -------------------------------------------------------------------------
    # 14. CRUD Administrativo Completo de Juízes
    # -------------------------------------------------------------------------
    def test_judge_crud(self):
        """Testa criação, listagem, edição e exclusão de juiz pelo Administrador."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Criar Juiz
        status, _, data, _ = self.client.post("/api/admin/judges", body={
            "name": "Juiz Perito",
            "email": "perito@sistema.com",
            "password": "senhaSegura123"
        }, headers=headers)
        self.assertEqual(status, 201)
        judge_id = data["id"]

        # Atualizar Juiz
        status_up, _, _, _ = self.client.put(f"/api/admin/judges/{judge_id}", body={
            "name": "Juiz Perito Atualizado",
            "email": "perito_novo@sistema.com"
        }, headers=headers)
        self.assertEqual(status_up, 200)

        # Excluir Juiz
        status_del, _, data_del, _ = self.client.delete(f"/api/admin/judges/{judge_id}", headers=headers)
        self.assertEqual(status_del, 200)
        self.assertTrue(data_del.get("success"))

    # -------------------------------------------------------------------------
    # 15. Inscrição Sequencial Automática de Candidatos
    # -------------------------------------------------------------------------
    def test_candidate_sequential_numbering(self):
        """Verifica que o número de inscrição é gerado automaticamente e é imutável."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 4 candidatos já foram criados no seed com números "01", "02", "03", "04"
        # O próximo candidato deve receber "05" automaticamente
        status, _, data, _ = self.client.post("/api/admin/candidates", body={
            "name": "Candidato Cinco",
            "description": "Teste sequencial"
        }, headers=headers)
        self.assertEqual(status, 201)
        self.assertEqual(data.get("number"), "05")
        cand_id = data["id"]

        # Tentar alterar o número via PUT não deve ter efeito
        status_up, _, _, _ = self.client.put(f"/api/admin/candidates/{cand_id}", body={
            "name": "Candidato Cinco Modificado",
            "number": "999",  # Tentativa de burlar
            "description": "Nova descrição"
        }, headers=headers)
        self.assertEqual(status_up, 200)

        # Consultar lista e verificar que continua "05"
        _, _, list_data, _ = self.client.get("/api/admin/candidates", headers=headers)
        cand_found = next((c for c in list_data["candidates"] if c["id"] == cand_id), None)
        self.assertIsNotNone(cand_found)
        self.assertEqual(cand_found["number"], "05")
        self.assertEqual(cand_found["name"], "Candidato Cinco Modificado")

    # -------------------------------------------------------------------------
    # 16. Importação em Lote via TXT
    # -------------------------------------------------------------------------
    def test_bulk_candidate_import(self):
        """Testa importação em lote com atribuição sequencial de números."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Importar lista de 3 candidatos
        names = ["Aline Torres", "Bruno Covas", "Carla Dias"]
        status, _, data, _ = self.client.post("/api/admin/candidates/bulk-import", body={
            "names": names
        }, headers=headers)
        self.assertEqual(status, 201)
        self.assertEqual(data["count"], 3)
        self.assertEqual(len(data["candidates"]), 3)

        # Também testa envio via texto quebrado por linhas
        text_payload = "Danilo Gentili\nEduardo Kobra\n\nFabiana Karla\n"
        status2, _, data2, _ = self.client.post("/api/admin/candidates/bulk-import", body={
            "text": text_payload
        }, headers=headers)
        self.assertEqual(status2, 201)
        self.assertEqual(data2["count"], 3)

    # -------------------------------------------------------------------------
    # 17. Campanhas de Votação e Limpeza de Candidatos da Campanha Atual
    # -------------------------------------------------------------------------
    def test_voting_campaigns_and_clear_candidates(self):
        """Testa criação de nova campanha (do zero), alternância e limpeza de candidatos."""
        headers = {"Authorization": f"Bearer {self.admin_token}"}

        # 1. Listar campanhas atuais (campanha 1 existe)
        status, _, camp_data, _ = self.client.get("/api/admin/campaigns", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(camp_data["active_campaign_id"], 1)

        # 2. Criar nova campanha
        status_new, _, new_camp, _ = self.client.post("/api/admin/campaigns", body={
            "name": "Etapa Regional 2026",
            "description": "Segunda etapa eliminatória"
        }, headers=headers)
        self.assertEqual(status_new, 201)
        new_camp_id = new_camp["id"]

        # 3. Na nova campanha ativa, a lista de candidatos deve estar vazia (iniciar do zero)
        _, _, cand_res, _ = self.client.get("/api/admin/candidates", headers=headers)
        self.assertEqual(len(cand_res["candidates"]), 0)

        # 4. Adicionar um candidato na nova campanha (deve começar no "01")
        status_c, _, c_data, _ = self.client.post("/api/admin/candidates", body={
            "name": "Primeiro Candidato Regional"
        }, headers=headers)
        self.assertEqual(status_c, 201)
        self.assertEqual(c_data["number"], "01")

        # 5. Limpar todos os candidatos da campanha atual
        status_clear, _, clear_data, _ = self.client.delete("/api/admin/candidates/clear-current-campaign", headers=headers)
        self.assertEqual(status_clear, 200)
        self.assertEqual(clear_data["deleted_count"], 1)

        # Verificar que a lista está vazia de novo
        _, _, cand_empty, _ = self.client.get("/api/admin/candidates", headers=headers)
        self.assertEqual(len(cand_empty["candidates"]), 0)

        # 6. Reativar a primeira campanha (Campanha Principal)
        status_act, _, act_data, _ = self.client.post("/api/admin/campaigns/1/activate", headers=headers)
        self.assertEqual(status_act, 200)
        self.assertEqual(act_data["active_campaign_id"], 1)

        # Candidatos da campanha 1 continuam intactos
        _, _, cand_orig, _ = self.client.get("/api/admin/candidates", headers=headers)
        self.assertGreaterEqual(len(cand_orig["candidates"]), 4)

    # -------------------------------------------------------------------------
    # 19. Segurança da Rota Pública e Reset de Senha de Juiz pelo Admin
    # -------------------------------------------------------------------------
    def test_judge_password_reset_and_public_info_security(self):
        """
        Garante que:
        1. /api/public/info não vaze lista de usuários ou credenciais.
        2. Apenas administradores consigam redefinir a senha de juízes.
        3. O juiz consiga se autenticar com a nova senha redefinida.
        4. A lista administrativa de juízes não exponha hash ou senhas em texto plano.
        """
        # 1. Rota pública não deve conter campo 'users'
        status_pub, _, pub_data, _ = self.client.get("/api/public/info")
        self.assertEqual(status_pub, 200)
        self.assertNotIn("users", pub_data)

        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        judge_headers = {"Authorization": f"Bearer {self.judge_token}"}

        # 2. Listagem de juízes pelo admin não expõe senha
        status_j, _, j_data, _ = self.client.get("/api/admin/judges", headers=admin_headers)
        self.assertEqual(status_j, 200)
        for judge in j_data["judges"]:
            self.assertNotIn("password", judge)
            self.assertNotIn("password_hash", judge)
            self.assertIn("name", judge)
            self.assertIn("email", judge)

        # 3. Juiz tentando redefinir senha de outro juiz deve receber 403 Forbidden
        status_denied, _, _, _ = self.client.post("/api/admin/judges/2/reset-password", body={
            "password": "tentativa_juiz"
        }, headers=judge_headers)
        self.assertEqual(status_denied, 403)

        # 4. Admin redefine a senha do primeiro juiz da lista
        target_judge = j_data["judges"][0]
        judge_id = target_judge["id"]
        judge_email = target_judge["email"]
        nova_senha = "NovaSenha@2026"

        status_reset, _, reset_data, _ = self.client.post(f"/api/admin/judges/{judge_id}/reset-password", body={
            "password": nova_senha
        }, headers=admin_headers)
        self.assertEqual(status_reset, 200)
        self.assertTrue(reset_data.get("success"))

        # 5. Juiz faz login com a nova senha
        status_login, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": judge_email,
            "password": nova_senha
        })
        self.assertEqual(status_login, 200)
        self.assertTrue(login_data.get("success"))
        self.assertIn("token", login_data)

        # Antiga senha não deve mais funcionar
        status_old, _, _, _ = self.client.post("/api/auth/login", body={
            "email": judge_email,
            "password": "juiz123"
        })
        self.assertEqual(status_old, 401)

    def test_session_active_user_flow(self):
        """1. Cenário: Usuário permanece ativo: sessão continua funcionando normalmente."""
        status, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        self.assertEqual(status, 200)
        token = login_data["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Acesso a rota protegida com usuário ativo
        status_me, _, me_data, _ = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(status_me, 200)
        self.assertTrue(me_data["success"])
        self.assertEqual(me_data["user"]["email"], "admin@sistema.com")

        # Status da sessão retorna ativo com tempos restantes
        status_s, _, s_data, _ = self.client.get("/api/auth/session-status", headers=headers)
        self.assertEqual(status_s, 200)
        self.assertTrue(s_data["active"])
        self.assertGreater(s_data["inactivity_remaining_seconds"], 0)

    def test_session_inactivity_timeout_and_protection(self):
        """2 e 5. Cenário: Inatividade de 15 minutos encerra sessão e bloqueia rotas protegidas."""
        status, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        self.assertEqual(status, 200)
        token = login_data["token"]
        session_id = login_data["session_id"]
        headers = {"Authorization": f"Bearer {token}"}

        # Simular que se passaram 15 minutos e 5 segundos sem qualquer interação (905 segundos)
        conn = get_db_connection(self.temp_db_path)
        try:
            import time
            now = int(time.time())
            conn.execute("UPDATE user_sessions SET last_activity = ? WHERE session_id = ?", (now - 905, session_id))
            conn.commit()
        finally:
            conn.close()

        # Tentar acessar rota protegida após expiração de inatividade
        status_dash, _, err_data, _ = self.client.get("/api/admin/dashboard", headers=headers)
        self.assertEqual(status_dash, 401)
        self.assertFalse(err_data["success"])
        self.assertEqual(err_data.get("reason"), "INACTIVITY_TIMEOUT")

        # Verificar se sessão foi marcada inativa no banco
        conn = get_db_connection(self.temp_db_path)
        try:
            row = conn.execute("SELECT is_active FROM user_sessions WHERE session_id = ?", (session_id,)).fetchone()
            self.assertEqual(row["is_active"], 0)
        finally:
            conn.close()

    def test_session_refresh_continue_connected(self):
        """3. Cenário: Usuário clica em 'Continuar conectado' e a sessão é renovada."""
        status, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        token = login_data["token"]
        session_id = login_data["session_id"]
        headers = {"Authorization": f"Bearer {token}"}

        # Simular 13 minutos de inatividade (780 segundos)
        import time
        now = int(time.time())
        conn = get_db_connection(self.temp_db_path)
        try:
            conn.execute("UPDATE user_sessions SET last_activity = ? WHERE session_id = ?", (now - 780, session_id))
            conn.commit()
        finally:
            conn.close()

        # Usuário clica em 'Continuar conectado' -> chamada POST /api/auth/refresh
        status_ref, _, ref_data, _ = self.client.post("/api/auth/refresh", headers=headers)
        self.assertEqual(status_ref, 200)
        self.assertTrue(ref_data["success"])
        self.assertEqual(ref_data["inactivity_remaining_seconds"], 900)

        # Confirmar que last_activity no banco foi atualizado para o tempo presente
        conn = get_db_connection(self.temp_db_path)
        try:
            row = conn.execute("SELECT last_activity FROM user_sessions WHERE session_id = ?", (session_id,)).fetchone()
            self.assertGreaterEqual(row["last_activity"], now)
        finally:
            conn.close()

    def test_session_max_lifetime_8_hours_limit(self):
        """9. Cenário: Sessão atinge limite absoluto de 8 horas e exige novo login."""
        status, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        token = login_data["token"]
        session_id = login_data["session_id"]
        headers = {"Authorization": f"Bearer {token}"}

        # Simular que a sessão foi criada há 8 horas e 10 segundos
        import time
        now = int(time.time())
        conn = get_db_connection(self.temp_db_path)
        try:
            conn.execute("""
                UPDATE user_sessions 
                SET created_at = ?, last_activity = ? 
                WHERE session_id = ?
            """, (now - (8 * 3600 + 10), now, session_id))
            conn.commit()
        finally:
            conn.close()

        # Tentar acessar rota protegida ou renovar sessão
        status_dash, _, err_dash, _ = self.client.get("/api/admin/dashboard", headers=headers)
        self.assertEqual(status_dash, 401)
        self.assertEqual(err_dash.get("reason"), "MAX_LIFETIME_EXCEEDED")

        # Tentar renovar também é rejeitado após 8 horas
        status_ref, _, err_ref, _ = self.client.post("/api/auth/refresh", headers=headers)
        self.assertEqual(status_ref, 401)
        self.assertEqual(err_ref.get("reason"), "MAX_LIFETIME_EXCEEDED")

    def test_manual_logout_invalidates_session(self):
        """6. Cenário: Logout manual invalida imediatamente a sessão no servidor."""
        status, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        token = login_data["token"]
        session_id = login_data["session_id"]
        headers = {"Authorization": f"Bearer {token}"}

        # Logout manual
        status_out, _, out_data, _ = self.client.post("/api/auth/logout", headers=headers)
        self.assertEqual(status_out, 200)
        self.assertTrue(out_data["success"])

        # Sessão deve estar inativa no banco
        conn = get_db_connection(self.temp_db_path)
        try:
            row = conn.execute("SELECT is_active FROM user_sessions WHERE session_id = ?", (session_id,)).fetchone()
            self.assertEqual(row["is_active"], 0)
        finally:
            conn.close()

        # Próxima tentativa de acesso deve ser rejeitada com 401
        status_denied, _, _, _ = self.client.get("/api/admin/dashboard", headers=headers)
        self.assertEqual(status_denied, 401)

    def test_background_poll_does_not_reset_inactivity(self):
        """Cenário: Chamadas automáticas de API em segundo plano NÃO contam como atividade."""
        status, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        session_id = login_data["session_id"]
        token = login_data["token"]

        import time
        now = int(time.time())
        initial_activity = now - 500  # 500 segundos atrás

        conn = get_db_connection(self.temp_db_path)
        try:
            conn.execute("UPDATE user_sessions SET last_activity = ? WHERE session_id = ?", (initial_activity, session_id))
            conn.commit()
        finally:
            conn.close()

        # Requisição com header de background poll
        bg_headers = {
            "Authorization": f"Bearer {token}",
            "X-Background-Poll": "1"
        }
        status_poll, _, _, _ = self.client.get("/api/admin/dashboard", headers=bg_headers)
        self.assertEqual(status_poll, 200)

        # Confirmar que last_activity NÃO foi atualizado para now
        conn = get_db_connection(self.temp_db_path)
        try:
            row = conn.execute("SELECT last_activity FROM user_sessions WHERE session_id = ?", (session_id,)).fetchone()
            self.assertEqual(row["last_activity"], initial_activity)
        finally:
            conn.close()

    def test_admin_change_password_full_security(self):
        """Cenário: Alteração segura de senha do Administrador Geral."""
        # 1. Login inicial com senha padrão
        status, _, login_data, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        self.assertEqual(status, 200)
        admin_token = login_data["token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        judge_headers = {"Authorization": f"Bearer {self.judge_token}"}

        # 2. Juiz tenta alterar senha do admin -> 403 Forbidden
        status_j, _, _, _ = self.client.post("/api/admin/security/password", body={
            "current_password": "qualquer_coisa",
            "new_password": "SenhaJuizTentando@123",
            "confirm_password": "SenhaJuizTentando@123"
        }, headers=judge_headers)
        self.assertEqual(status_j, 403)

        # 3. Senha atual incorreta
        status_w, _, err_w, _ = self.client.post("/api/admin/security/password", body={
            "current_password": "senha_errada_aqui",
            "new_password": "NovaSenhaForte2026!",
            "confirm_password": "NovaSenhaForte2026!"
        }, headers=admin_headers)
        self.assertEqual(status_w, 400)
        self.assertIn("incorreta", err_w["error"].lower())

        # 4. Senha com menos de 8 caracteres
        status_short, _, err_short, _ = self.client.post("/api/admin/security/password", body={
            "current_password": "admin123",
            "new_password": "curta",
            "confirm_password": "curta"
        }, headers=admin_headers)
        self.assertEqual(status_short, 400)
        self.assertIn("8 caracteres", err_short["error"])

        # 5. Confirmação diferente da nova senha
        status_mismatch, _, err_mismatch, _ = self.client.post("/api/admin/security/password", body={
            "current_password": "admin123",
            "new_password": "NovaSenhaForte2026!",
            "confirm_password": "OutraSenhaDiferente!"
        }, headers=admin_headers)
        self.assertEqual(status_mismatch, 400)
        self.assertIn("não coincidem", err_mismatch["error"])

        # 6. Alteração com sucesso
        nova_senha_admin = "AdminForte@2026!#"
        status_ok, _, ok_data, _ = self.client.post("/api/admin/security/password", body={
            "current_password": "admin123",
            "new_password": nova_senha_admin,
            "confirm_password": nova_senha_admin
        }, headers=admin_headers)
        self.assertEqual(status_ok, 200)
        self.assertTrue(ok_data["success"])

        # 7. Antiga senha 'admin123' deixa de funcionar
        status_old, _, _, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": "admin123"
        })
        self.assertEqual(status_old, 401)

        # 8. Nova senha funciona perfeitamente
        status_new, _, new_login, _ = self.client.post("/api/auth/login", body={
            "email": "admin@sistema.com",
            "password": nova_senha_admin
        })
        self.assertEqual(status_new, 200)
        self.assertTrue(new_login["success"])
        self.assertEqual(new_login["user"]["role"], "ADMIN")

        # 9. Validar que o hash no banco preserva PBKDF2
        conn = get_db_connection(self.temp_db_path)
        try:
            row = conn.execute("SELECT password_hash FROM users WHERE email = 'admin@sistema.com'").fetchone()
            self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$100000$"))
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # 27. Validação do Dashboard do ADM: Pódio e Top 3 Colocados
    # -------------------------------------------------------------------------
    def test_admin_dashboard_top_three_podium(self):
        """
        Garante que o endpoint do Dashboard do ADM (/api/admin/dashboard)
        disponibilize os dados de rankings para apresentação dos 3 primeiros colocados.
        """
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        status, _, data, _ = self.client.get("/api/admin/dashboard", headers=admin_headers)
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        self.assertIn("rankings", data)
        self.assertIn("stats", data)
        self.assertIn("winners", data)
        self.assertIsInstance(data["rankings"], list)

        # Simular submissão de votos para 3 candidatos diferentes e validar o pódio
        judge_headers = {"Authorization": f"Bearer {self.judge_token}"}
        conn = get_db_connection(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM categories WHERE active = 1")
        cats = [r["id"] for r in cur.fetchall()]
        conn.close()

        # Candidato 1 recebe notas 10
        self.client.post("/api/judge/vote", body={
            "candidate_id": 1,
            "scores": {str(c): 10 for c in cats}
        }, headers=judge_headers)

        # Candidato 2 recebe notas 9
        self.client.post("/api/judge/vote", body={
            "candidate_id": 2,
            "scores": {str(c): 9 for c in cats}
        }, headers=judge_headers)

        # Candidato 3 recebe notas 8
        self.client.post("/api/judge/vote", body={
            "candidate_id": 3,
            "scores": {str(c): 8 for c in cats}
        }, headers=judge_headers)

        # Reconsultar dashboard
        status, _, data, _ = self.client.get("/api/admin/dashboard", headers=admin_headers)
        self.assertEqual(status, 200)
        rankings = data["rankings"]
        evaluated = [c for c in rankings if c["total_scores_count"] > 0]
        self.assertGreaterEqual(len(evaluated), 3)

        first = evaluated[0]
        second = evaluated[1]
        third = evaluated[2]

        self.assertEqual(first["rank"], 1)
        self.assertEqual(first["final_average_formatted"], "10.00")
        self.assertEqual(second["rank"], 2)
        self.assertEqual(second["final_average_formatted"], "9.00")
        self.assertEqual(third["rank"], 3)
        self.assertEqual(third["final_average_formatted"], "8.00")




if __name__ == "__main__":
    unittest.main()


