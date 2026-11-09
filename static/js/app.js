/**
 * SISTEMA DE AVALIAÇÃO DE CANDIDATOS POR JUÍZES
 * Aplicação Frontend SPA (Single Page Application)
 */

(function () {
  "use strict";

  // Estado da Aplicação
  const state = {
    token: localStorage.getItem("auth_token") || null,
    user: null,
    eventInfo: {},
    judge: {
      candidates: [],
      categories: [],
      progress: { evaluated_count: 0, total_candidates: 0, percentage: 0 },
      currentCandidate: null,
      selectedScores: {},
      filter: "pending",
      searchQuery: ""
    },
    admin: {
      currentTab: "tabDashboard",
      candidates: [],
      judges: [],
      categories: [],
      rankings: [],
      matrix: null,
      stats: null,
      settings: {},
      podiumRevealed: { 1: true, 2: true, 3: true },
      podiumCache: null
    }
  };

  // =========================================================================
  // Utilitários de Requisição HTTP (Fetch Wrapper)
  // =========================================================================

  async function apiRequest(endpoint, options = {}) {
    const headers = options.headers || {};
    headers["Accept"] = "application/json";

    if (options.background) {
      headers["X-Background-Poll"] = "1";
    }

    if (state.token) {
      headers["Authorization"] = `Bearer ${state.token}`;
    }

    if (options.body && typeof options.body === "object" && !(options.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(options.body);
    }

    try {
      const response = await fetch(endpoint, { ...options, headers });
      const data = await response.json().catch(() => ({}));

      if (response.status === 401) {
        // Sessão expirada ou não autenticada
        if (state.token) {
          const reason = data.reason || "";
          if (reason === "INACTIVITY_TIMEOUT") {
            handleSessionExpired("inactivity");
          } else if (reason === "MAX_LIFETIME_EXCEEDED") {
            handleSessionExpired("max_lifetime");
          } else {
            showToast(data.error || "Sessão expirada. Faça login novamente.", "error");
            logout();
          }
        }
        return { success: false, error: data.error || "Não autenticado.", status: 401, reason: data.reason };
      }

      if (!response.ok) {
        return { success: false, error: data.error || `Erro HTTP ${response.status}`, status: response.status, ...data };
      }

      return data;
    } catch (err) {
      console.error("Erro na requisição:", err);
      return { success: false, error: "Falha de comunicação com o servidor." };
    }
  }

  // =========================================================================
  // Notificações Toast
  // =========================================================================

  function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(10px)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // =========================================================================
  // Navegação entre Telas (Views)
  // =========================================================================

  function switchView(viewId) {
    const views = [
      "viewLogin",
      "viewJudge",
      "viewJudgeEvaluation",
      "viewAdmin",
      "viewPublicResults"
    ];

    views.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = id === viewId ? "block" : "none";
    });

    updateHeaderUI();
  }

  function updateHeaderUI() {
    const headerActions = document.getElementById("headerUserActions");
    const roleBadge = document.getElementById("roleBadge");
    const userNameSpan = document.getElementById("headerUserName");
    const statusBadge = document.getElementById("votingStatusBadge");
    const eventNameHeader = document.getElementById("headerEventName");

    if (state.eventInfo && state.eventInfo.event_name) {
      eventNameHeader.textContent = state.eventInfo.event_name;
    }

    // Status da Votação
    const status = state.eventInfo.voting_status || "OPEN";
    if (status === "OPEN") {
      statusBadge.textContent = "Votação Aberta";
      statusBadge.className = "badge badge-emerald";
    } else if (status === "PAUSED") {
      statusBadge.textContent = "Votação Pausada";
      statusBadge.className = "badge badge-amber";
    } else {
      statusBadge.textContent = "Votação Encerrada";
      statusBadge.className = "badge badge-slate";
    }

    if (state.user) {
      headerActions.style.display = "flex";
      userNameSpan.textContent = state.user.name;

      roleBadge.style.display = "inline-flex";
      if (state.user.role === "ADMIN") {
        roleBadge.textContent = "Administrador";
        roleBadge.className = "badge badge-outline";
      } else {
        roleBadge.textContent = "Juiz Avaliador";
        roleBadge.className = "badge badge-outline";
      }

      const campBadge = document.getElementById("headerCampaignBadge");
      if (campBadge) {
        if (state.activeCampaign && state.activeCampaign.name) {
          campBadge.textContent = state.activeCampaign.name;
          campBadge.style.display = "inline-flex";
        } else {
          campBadge.style.display = "none";
        }
      }
    } else {
      headerActions.style.display = "none";
      roleBadge.style.display = "none";
      const campBadge = document.getElementById("headerCampaignBadge");
      if (campBadge) campBadge.style.display = "none";
    }
  }

  // =========================================================================
  // Fluxo de Autenticação
  // =========================================================================

  async function checkAuthSession() {
    const publicInfo = await apiRequest("/api/public/info");
    if (publicInfo.success) {
      state.eventInfo = publicInfo;
    }

    if (!state.token) {
      switchView("viewLogin");
      return;
    }

    const res = await apiRequest("/api/auth/me");
    if (res.success && res.user) {
      state.user = res.user;
      routeUserByRole();
    } else {
      logout();
    }
  }

  function routeUserByRole() {
    if (!state.user) {
      switchView("viewLogin");
      return;
    }

    if (state.user.role === "ADMIN") {
      switchView("viewAdmin");
      initAdminDashboard();
    } else if (state.user.role === "JUDGE") {
      switchView("viewJudge");
      loadJudgeVotingScreen();
    } else {
      switchView("viewLogin");
    }
  }

  // =========================================================================
  // Gerenciamento de Sessão, Inatividade (13+2=15 min) e Expiração Máxima (8h)
  // =========================================================================

  const SESSION_CONFIG = {
    INACTIVITY_TIMEOUT_MS: 15 * 60 * 1000,       // 15 minutos de inatividade
    INACTIVITY_WARNING_MS: 13 * 60 * 1000,       // 13 minutos até exibir aviso
    COUNTDOWN_DURATION_MS: 2 * 60 * 1000,        // 2 minutos de contagem regressiva
    MAX_SESSION_LIFETIME_MS: 8 * 60 * 60 * 1000, // 8 horas de duração máxima
    ACTIVITY_THROTTLE_MS: 4000                   // 4 segundos de throttle para registrar atividade
  };

  let sessionCheckInterval = null;
  let lastRecordedActivity = Date.now();
  let isWarningModalOpen = false;
  let isSessionTerminating = false;

  function initSessionManager() {
    // Eventos de interação humana real
    const activityEvents = [
      "mousemove", "mousedown", "click", "keydown",
      "input", "touchstart", "touchend", "scroll", "wheel"
    ];

    activityEvents.forEach(evt => {
      window.addEventListener(evt, handleUserActivity, { passive: true });
    });

    // Sincronização multi-abas
    window.addEventListener("storage", handleMultiTabStorageEvent);

    // Botão Continuar Conectado
    const btnStay = document.getElementById("btnSessionStayConnected");
    if (btnStay) {
      btnStay.addEventListener("click", () => {
        renewSession();
      });
    }

    // Botão Sair Agora no modal
    const btnLogoutNow = document.getElementById("btnSessionLogoutNow");
    if (btnLogoutNow) {
      btnLogoutNow.addEventListener("click", () => {
        closeSessionTimeoutModal();
        logout("Você encerrou a sessão.");
      });
    }

    // Formulário de alteração de senha do Administrador
    const formAdminPwd = document.getElementById("formAdminChangePassword");
    if (formAdminPwd) {
      formAdminPwd.addEventListener("submit", handleAdminPasswordSubmit);
    }

    startSessionMonitor();
  }

  function handleUserActivity() {
    if (!state.token || isSessionTerminating) return;

    const now = Date.now();
    // Se o modal de aviso estava aberto e o usuário interagiu, fecha modal e renova
    if (isWarningModalOpen) {
      renewSession();
      return;
    }

    if (now - lastRecordedActivity >= SESSION_CONFIG.ACTIVITY_THROTTLE_MS) {
      lastRecordedActivity = now;
      try {
        localStorage.setItem("auth_last_activity", now.toString());
      } catch (e) {}
    }
  }

  function handleMultiTabStorageEvent(e) {
    if (e.key === "auth_last_activity" && e.newValue) {
      const remoteActivity = parseInt(e.newValue, 10);
      if (!isNaN(remoteActivity) && remoteActivity > lastRecordedActivity) {
        lastRecordedActivity = remoteActivity;
        if (isWarningModalOpen) {
          closeSessionTimeoutModal();
        }
      }
    } else if (e.key === "auth_session_event" && e.newValue) {
      try {
        const payload = JSON.parse(e.newValue);
        if (payload.action === "LOGOUT") {
          terminateSessionLocally("Sua sessão foi encerrada em outra aba.");
        } else if (payload.action === "EXPIRED_INACTIVITY") {
          terminateSessionLocally("Sessão encerrada por inatividade (15 minutos sem interação).");
        } else if (payload.action === "EXPIRED_MAX_LIFETIME") {
          terminateSessionLocally("Sessão expirada: limite máximo de 8 horas atingido.");
        }
      } catch (err) {}
    } else if (e.key === "auth_token" && !e.newValue && state.token) {
      terminateSessionLocally("Sessão encerrada.");
    }
  }

  function startSessionMonitor() {
    if (sessionCheckInterval) clearInterval(sessionCheckInterval);
    sessionCheckInterval = setInterval(checkSessionTimers, 1000);
  }

  function checkSessionTimers() {
    if (!state.token || isSessionTerminating) {
      if (isWarningModalOpen) closeSessionTimeoutModal();
      return;
    }

    const now = Date.now();

    // 1. Validar Expiração Máxima de 8 horas desde o login
    const sessionCreatedAt = parseInt(localStorage.getItem("auth_session_created_at") || "0", 10);
    if (sessionCreatedAt > 0 && (now - sessionCreatedAt) >= SESSION_CONFIG.MAX_SESSION_LIFETIME_MS) {
      handleSessionExpired("max_lifetime");
      return;
    }

    // 2. Validar Tempo de Inatividade
    const storedLastActivity = parseInt(localStorage.getItem("auth_last_activity") || "0", 10);
    const effectiveLastActivity = Math.max(lastRecordedActivity, storedLastActivity || 0);
    const inactiveDuration = now - effectiveLastActivity;

    if (inactiveDuration >= SESSION_CONFIG.INACTIVITY_TIMEOUT_MS) {
      // 15 minutos completados -> logout automático
      handleSessionExpired("inactivity");
    } else if (inactiveDuration >= SESSION_CONFIG.INACTIVITY_WARNING_MS) {
      // Entre 13 e 15 minutos -> exibe aviso com contagem regressiva de 2 minutos
      const remainingMs = SESSION_CONFIG.INACTIVITY_TIMEOUT_MS - inactiveDuration;
      openSessionTimeoutModal(remainingMs);
    } else {
      if (isWarningModalOpen) {
        closeSessionTimeoutModal();
      }
    }
  }

  function openSessionTimeoutModal(remainingMs) {
    const modal = document.getElementById("modalSessionTimeout");
    if (!modal) return;

    isWarningModalOpen = true;
    modal.style.display = "flex";

    const totalSeconds = Math.max(0, Math.ceil(remainingMs / 1000));
    const mins = Math.floor(totalSeconds / 60);
    const secs = totalSeconds % 60;
    const formatted = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;

    const countdownEl = document.getElementById("sessionCountdownDisplay");
    if (countdownEl) countdownEl.textContent = formatted;

    // Se estiver no perfil de juiz avaliando, destaca preservação de rascunho
    const draftNotice = document.getElementById("sessionDraftNotice");
    if (draftNotice) {
      const isEvaluating = state.judge && state.judge.currentCandidate;
      draftNotice.style.display = isEvaluating ? "block" : "none";
    }
  }

  function closeSessionTimeoutModal() {
    isWarningModalOpen = false;
    const modal = document.getElementById("modalSessionTimeout");
    if (modal) modal.style.display = "none";
  }

  async function renewSession() {
    closeSessionTimeoutModal();
    const now = Date.now();
    lastRecordedActivity = now;
    try {
      localStorage.setItem("auth_last_activity", now.toString());
    } catch (e) {}

    const res = await apiRequest("/api/auth/refresh", { method: "POST" });
    if (res.success) {
      showToast("Sessão renovada com sucesso!", "success");
    } else if (res.status === 401 || res.reason === "MAX_LIFETIME_EXCEEDED") {
      handleSessionExpired("max_lifetime");
    }
  }

  function handleSessionExpired(reason) {
    if (isSessionTerminating) return;
    isSessionTerminating = true;
    closeSessionTimeoutModal();

    let msg = "Sua sessão foi encerrada por inatividade (15 minutos sem interação).";
    let eventAction = "EXPIRED_INACTIVITY";
    if (reason === "max_lifetime") {
      msg = "Sua sessão atingiu o tempo limite máximo de 8 horas. Por motivos de segurança, faça login novamente.";
      eventAction = "EXPIRED_MAX_LIFETIME";
    }

    try {
      localStorage.setItem("auth_session_event", JSON.stringify({
        action: eventAction,
        timestamp: Date.now()
      }));
    } catch (e) {}

    const oldToken = state.token;
    state.token = null;
    state.user = null;
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_session_created_at");

    if (oldToken) {
      fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Authorization": `Bearer ${oldToken}` }
      }).catch(() => {});
    }

    switchView("viewLogin");
    showToast(msg, "warning");

    setTimeout(() => {
      isSessionTerminating = false;
    }, 1000);
  }

  function terminateSessionLocally(message) {
    isSessionTerminating = true;
    closeSessionTimeoutModal();
    state.token = null;
    state.user = null;
    switchView("viewLogin");
    showToast(message, "info");
    setTimeout(() => {
      isSessionTerminating = false;
    }, 1000);
  }

  // =========================================================================
  // Preservação de Rascunhos de Avaliação dos Juízes
  // =========================================================================

  function getDraftKey(judgeId, candidateId) {
    return `draft_eval_${judgeId}_${candidateId}`;
  }

  function saveEvaluationDraft(judgeId, candidateId, scores) {
    if (!judgeId || !candidateId) return;
    try {
      localStorage.setItem(getDraftKey(judgeId, candidateId), JSON.stringify({
        scores: scores || {},
        updatedAt: Date.now()
      }));
    } catch (e) {}
  }

  function loadEvaluationDraft(judgeId, candidateId) {
    if (!judgeId || !candidateId) return null;
    try {
      const raw = localStorage.getItem(getDraftKey(judgeId, candidateId));
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function clearEvaluationDraft(judgeId, candidateId) {
    if (!judgeId || !candidateId) return;
    try {
      localStorage.removeItem(getDraftKey(judgeId, candidateId));
    } catch (e) {}
  }

  // =========================================================================
  // Segurança e Senha do Administrador
  // =========================================================================

  async function handleAdminPasswordSubmit(e) {
    e.preventDefault();
    const currentPassword = document.getElementById("adminCurrentPassword").value;
    const newPassword = document.getElementById("adminNewPassword").value;
    const confirmPassword = document.getElementById("adminConfirmPassword").value;
    const btn = document.getElementById("btnSubmitAdminPassword");

    if (!currentPassword) {
      showToast("Informe a senha atual.", "error");
      return;
    }
    if (newPassword.length < 8) {
      showToast("A nova senha deve possuir no mínimo 8 caracteres.", "error");
      return;
    }
    if (newPassword !== confirmPassword) {
      showToast("A nova senha e a confirmação não coincidem.", "error");
      return;
    }

    btn.disabled = true;
    btn.innerHTML = "<span>Salvando...</span>";

    const res = await apiRequest("/api/admin/security/password", {
      method: "POST",
      body: {
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword
      }
    });

    btn.disabled = false;
    btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg><span>Salvar Nova Senha</span>`;

    if (res.success) {
      showToast(res.message || "Senha de administrador atualizada com sucesso!", "success");
      document.getElementById("formAdminChangePassword").reset();
    } else {
      showToast(res.error || "Erro ao atualizar senha.", "error");
    }
  }

  window.togglePasswordVisibility = function (inputId, btnEl) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === "password") {
      input.type = "text";
      btnEl.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>`;
    } else {
      input.type = "password";
      btnEl.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }
  };

  window.switchAdminTab = function (tabId) {
    document.querySelectorAll(".admin-nav-item").forEach(item => {
      if (item.getAttribute("data-tab") === tabId) item.classList.add("active");
      else item.classList.remove("active");
    });
    document.querySelectorAll(".admin-tab-pane").forEach(pane => {
      if (pane.id === tabId) pane.classList.add("active");
      else pane.classList.remove("active");
    });
    state.admin.currentTab = tabId;
    handleAdminTabLoad(tabId);
  };

  async function handleLoginSubmit(e) {
    e.preventDefault();
    const email = document.getElementById("loginEmail").value.trim();
    const password = document.getElementById("loginPassword").value;
    const btn = document.getElementById("btnLoginSubmit");

    btn.disabled = true;
    btn.innerHTML = "<span>Autenticando...</span>";

    const res = await apiRequest("/api/auth/login", {
      method: "POST",
      body: { email, password }
    });

    btn.disabled = false;
    btn.innerHTML = `<span>Entrar no Sistema</span><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>`;

    if (res.success && res.token) {
      state.token = res.token;
      state.user = res.user;
      const now = Date.now();
      lastRecordedActivity = now;
      localStorage.setItem("auth_token", res.token);
      localStorage.setItem("auth_session_created_at", now.toString());
      localStorage.setItem("auth_last_activity", now.toString());
      showToast(`Bem-vindo, ${res.user.name}!`, "success");
      routeUserByRole();
    } else {
      showToast(res.error || "Credenciais inválidas.", "error");
    }
  }

  function logout(customMessage) {
    closeSessionTimeoutModal();
    try {
      localStorage.setItem("auth_session_event", JSON.stringify({
        action: "LOGOUT",
        timestamp: Date.now()
      }));
    } catch (e) {}

    const oldToken = state.token;
    state.token = null;
    state.user = null;
    localStorage.removeItem("auth_token");
    localStorage.removeItem("auth_session_created_at");
    localStorage.removeItem("auth_last_activity");

    if (oldToken) {
      apiRequest("/api/auth/logout", { method: "POST" });
    }

    switchView("viewLogin");
    showToast(customMessage || "Você saiu do sistema.", "info");
  }

  // =========================================================================
  // Módulo do Juiz (Interface de Votação)
  // =========================================================================

  async function loadJudgeVotingScreen() {
    const res = await apiRequest("/api/judge/voting");
    if (!res.success) {
      showToast(res.error || "Erro ao carregar bancada de votação.", "error");
      return;
    }

    state.judge.candidates = res.candidates || [];
    state.judge.categories = res.categories || [];
    state.judge.progress = res.progress || {};
    state.eventInfo.voting_status = res.voting_status;
    state.eventInfo.allow_corrections = res.allow_corrections;
    if (res.campaign) {
      state.activeCampaign = res.campaign;
      updateHeaderUI();
    }

    renderJudgeProgress();
    renderJudgeCandidatesGrid();
  }

  function renderJudgeProgress() {
    const prog = state.judge.progress;
    const fractionEl = document.getElementById("judgeProgressFraction");
    const barEl = document.getElementById("judgeProgressBar");
    const alertEl = document.getElementById("judgeVotingClosedAlert");

    fractionEl.textContent = `${prog.evaluated_count} / ${prog.total_candidates}`;
    barEl.style.width = `${prog.percentage}%`;

    const countAll = state.judge.candidates.length;
    const countEvaluated = state.judge.candidates.filter(c => c.is_evaluated).length;
    const countPending = countAll - countEvaluated;

    document.getElementById("countAll").textContent = countAll;
    document.getElementById("countEvaluated").textContent = countEvaluated;
    document.getElementById("countPending").textContent = countPending;

    if (state.eventInfo.voting_status === "CLOSED") {
      alertEl.style.display = "flex";
    } else {
      alertEl.style.display = "none";
    }
  }

  function renderJudgeCandidatesGrid() {
    const grid = document.getElementById("judgeCandidatesGrid");
    grid.innerHTML = "";

    const filter = state.judge.filter;
    const query = state.judge.searchQuery.toLowerCase();

    const sorted = state.judge.candidates.slice().sort((a, b) => {
      if (a.is_evaluated === b.is_evaluated) return 0;
      return a.is_evaluated ? 1 : -1; // pending first
    });
    const filtered = sorted.filter(c => {
      if (filter === "pending" && c.is_evaluated) return false;
      if (filter === "evaluated" && !c.is_evaluated) return false;
      if (query && !c.name.toLowerCase().includes(query) && !(c.number || "").includes(query)) return false;
      return true;
    });

    if (filtered.length === 0) {
      grid.innerHTML = `
        <div style="grid-column: 1 / -1; text-align: center; padding: 3rem; background: white; border-radius: 12px; border: 1px dashed var(--slate-300);">
          <p style="color: var(--slate-500); font-weight: 600;">Nenhum candidato encontrado neste filtro.</p>
        </div>
      `;
      return;
    }

    filtered.forEach(cand => {
      const card = document.createElement("div");
      card.className = `candidate-judge-card ${cand.is_evaluated ? "is-evaluated" : "is-pending"}`;

      const photoUrl = cand.photo_url || "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=300&auto=format&fit=crop&q=80";
      const statusBadgeHtml = cand.is_evaluated
        ? `<span class="badge badge-emerald card-badge-status">Concluído ✓</span>`
        : `<span class="badge badge-amber card-badge-status">Pendente ⏳</span>`;

      card.innerHTML = `
        <div class="card-candidate-header-clean">
          <div class="card-candidate-badge-num">Nº ${cand.number || cand.id}</div>
          ${statusBadgeHtml}
        </div>
        <div class="card-candidate-body">
          <h3 class="card-candidate-title">${cand.name}</h3>
          <p class="card-candidate-desc">${cand.description || "Sem descrição informada."}</p>
          <div class="card-candidate-footer">
            <button class="btn btn-sm btn-block ${cand.is_evaluated ? "btn-outline" : "btn-primary"}" data-cand-id="${cand.id}">
              ${cand.is_evaluated ? "Revisar Notas" : "Avaliar Candidato"}
            </button>
          </div>
        </div>
      `;

      card.querySelector("button").addEventListener("click", () => {
        openJudgeEvaluationScreen(cand);
      });

      grid.appendChild(card);
    });
  }

  function openJudgeEvaluationScreen(candidate) {
    state.judge.currentCandidate = candidate;
    state.judge.selectedScores = { ...(candidate.scores || {}) };

    // Recuperação de rascunho salvo caso o juiz tenha saído ou a sessão tenha caído
    if (state.user && state.user.id) {
      const draft = loadEvaluationDraft(state.user.id, candidate.id);
      if (draft && draft.scores && Object.keys(draft.scores).length > 0) {
        state.judge.selectedScores = { ...state.judge.selectedScores, ...draft.scores };
        showToast("Rascunho de notas recuperado automaticamente.", "info");
      }
    }

    document.getElementById("evalCandidateName").textContent = candidate.name;
    document.getElementById("evalCandidateNumber").textContent = `Nº ${candidate.number || candidate.id}`;
    document.getElementById("evalCandidateDesc").textContent = candidate.description || "Apresentação sem descrição.";

    const statusEl = document.getElementById("evalCurrentStatus");
    if (candidate.is_evaluated) {
      statusEl.innerHTML = `<span class="badge badge-emerald">Avaliação Já Realizada</span>`;
    } else {
      statusEl.innerHTML = `<span class="badge badge-amber">Avaliação Pendente</span>`;
    }

    renderEvaluationCategories();
    switchView("viewJudgeEvaluation");
  }

  function renderEvaluationCategories() {
    const list = document.getElementById("evalCategoriesList");
    list.innerHTML = "";

    const categories = state.judge.categories;
    const isClosed = state.eventInfo.voting_status === "CLOSED";
    const allowCorrections = state.eventInfo.allow_corrections;
    const isEvaluated = state.judge.currentCandidate && state.judge.currentCandidate.is_evaluated;

    const readOnly = isClosed || (isEvaluated && !allowCorrections);

    categories.forEach(cat => {
      const block = document.createElement("div");
      block.className = "category-eval-block";

      const currentScore = state.judge.selectedScores[cat.id] || null;

      block.innerHTML = `
        <div class="category-header-info">
          <span class="category-name-title">${cat.name}</span>
          <span class="category-selected-score" id="scoreDisplay_${cat.id}">
            ${currentScore !== null ? `Nota: ${currentScore}` : "Selecione a nota"}
          </span>
        </div>
        <p class="category-desc-info">${cat.description || "Atribua uma nota inteira de 1 a 10 para este critério."}</p>
        <div class="score-buttons-group" id="scoreGroup_${cat.id}"></div>
      `;

      const group = block.querySelector(`#scoreGroup_${cat.id}`);

      // Botões táteis de 1 a 10
      for (let scoreVal = 1; scoreVal <= 10; scoreVal++) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = `btn-score ${currentScore === scoreVal ? "active" : ""}`;
        btn.textContent = scoreVal;
        btn.disabled = readOnly;

        btn.addEventListener("click", () => {
          if (readOnly) return;
          state.judge.selectedScores[cat.id] = scoreVal;

          // Salvar rascunho seguro a cada nota selecionada para evitar perdas
          if (state.user && state.judge.currentCandidate) {
            saveEvaluationDraft(state.user.id, state.judge.currentCandidate.id, state.judge.selectedScores);
          }

          // Atualizar estado visual
          group.querySelectorAll(".btn-score").forEach(b => b.classList.remove("active"));
          btn.classList.add("active");
          block.querySelector(`#scoreDisplay_${cat.id}`).textContent = `Nota: ${scoreVal}`;
        });

        group.appendChild(btn);
      }

      list.appendChild(block);
    });

    const confirmBtn = document.getElementById("btnConfirmEvaluation");
    const confirmText = document.getElementById("btnConfirmText");

    if (readOnly) {
      confirmBtn.disabled = true;
      confirmText.textContent = isClosed ? "Votação Encerrada" : "Alterações Bloqueadas pelo Administrador";
    } else {
      confirmBtn.disabled = false;
      confirmText.textContent = isEvaluated ? "Salvar e Atualizar Avaliação" : "Salvar e Confirmar Avaliação";
    }
  }

  async function submitJudgeEvaluation() {
    const candidate = state.judge.currentCandidate;
    if (!candidate) return;

    if (!state.token) {
      showToast("Sessão expirada. Seus dados continuam salvos em rascunho. Faça login para confirmar.", "warning");
      switchView("viewLogin");
      return;
    }

    const categories = state.judge.categories;
    const scores = state.judge.selectedScores;

    // Validar se todas as categorias receberam notas
    for (const cat of categories) {
      const score = scores[cat.id];
      if (score === undefined || score === null || score < 1 || score > 10) {
        showToast(`Por favor, atribua uma nota de 1 a 10 para a categoria: ${cat.name}`, "error");
        return;
      }
    }

    const confirmBtn = document.getElementById("btnConfirmEvaluation");
    confirmBtn.disabled = true;

    const res = await apiRequest("/api/judge/vote", {
      method: "POST",
      body: {
        candidate_id: candidate.id,
        scores: scores
      }
    });

    confirmBtn.disabled = false;

    if (res.success) {
      // Limpar rascunho com sucesso confirmado
      if (state.user) {
        clearEvaluationDraft(state.user.id, candidate.id);
      }
      showToast(`Avaliação de ${candidate.name} confirmada com sucesso!`, "success");
      await loadJudgeVotingScreen();
      switchView("viewJudge");
    } else {
      showToast(res.error || "Erro ao salvar avaliação.", "error");
    }
  }

  // =========================================================================
  // Módulo Administrativo (Dashboard, Rankings, CRUDs, Governança)
  // =========================================================================

  function initAdminDashboard() {
    bindAdminNav();
    loadAdminDashboard();
  }

  function bindAdminNav() {
    document.querySelectorAll(".admin-nav-item").forEach(item => {
      item.addEventListener("click", () => {
        document.querySelectorAll(".admin-nav-item").forEach(i => i.classList.remove("active"));
        document.querySelectorAll(".admin-tab-pane").forEach(p => p.classList.remove("active"));

        item.classList.add("active");
        const tabId = item.getAttribute("data-tab");
        const pane = document.getElementById(tabId);
        if (pane) pane.classList.add("active");

        state.admin.currentTab = tabId;
        handleAdminTabLoad(tabId);
      });
    });
  }

  function handleAdminTabLoad(tabId) {
    if (tabId === "tabDashboard") loadAdminDashboard();
    else if (tabId === "tabRankings") loadAdminRankings();
    else if (tabId === "tabMonitoring") loadAdminMonitoring();
    else if (tabId === "tabCandidates") loadAdminCandidates();
    else if (tabId === "tabJudges") loadAdminJudges();
    else if (tabId === "tabCategories") loadAdminCategories();
    else if (tabId === "tabSettings") loadAdminSettings();
  }

  async function loadAdminDashboard() {
    const res = await apiRequest("/api/admin/dashboard");
    if (!res.success) {
      showToast(res.error || "Erro ao carregar dashboard.", "error");
      return;
    }

    const stats = res.stats;
    state.admin.stats = stats;
    state.eventInfo = { ...state.eventInfo, ...stats };
    if (stats.active_campaign) {
      state.activeCampaign = stats.active_campaign;
    }
    updateHeaderUI();

    document.getElementById("kpiTotalCandidates").textContent = stats.total_candidates;
    document.getElementById("kpiTotalJudges").textContent = stats.total_judges;
    document.getElementById("kpiSubmissionsDone").textContent = `${stats.completed_submissions} de ${stats.expected_submissions}`;
    document.getElementById("kpiSubmissionsPending").textContent = `${stats.pending_submissions} pendentes`;
    document.getElementById("kpiCompletionPercentage").textContent = `${stats.completion_percentage}%`;
    document.getElementById("kpiTotalNotes").textContent = `${stats.total_evaluations_recorded} notas registradas`;

    state.admin.rankings = res.rankings || [];
    renderTopThreePodium(res.rankings || [], res.winners, res.is_winner_tie, stats.voting_status, stats.show_provisional_winner);
  }

  function renderTopThreePodium(rankings, winners, isTie, votingStatus, showProvisional) {
    state.admin.podiumCache = { rankings, winners, isTie, votingStatus, showProvisional };
    renderTopThreePodiumUI();
  }

  function renderTopThreePodiumUI() {
    const container = document.getElementById("winnerSpotlight");
    if (!container) return;

    const cache = state.admin.podiumCache;
    if (!cache) return;

    const rankings = cache.rankings || [];
    const votingStatus = cache.votingStatus;
    const isClosed = votingStatus === "CLOSED";

    // Filtrar candidatos com notas válidas
    const evaluatedRankings = rankings.filter(c => c.total_scores_count > 0);

    if (evaluatedRankings.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 2rem 1rem;">
          <div style="font-size: 2.2rem; margin-bottom: 0.5rem;">🏆</div>
          <h3 style="color: var(--kor-orange); font-size: 1.25rem; font-weight: 700;">Aguardando Primeiras Avaliações</h3>
          <p style="color: #cbd5e1; font-size: 0.88rem; margin-top: 0.35rem; max-width: 500px; margin-left: auto; margin-right: auto;">
            Assim que os juízes confirmarem suas notas, os 3 primeiros colocados e a classificação serão computados automaticamente.
          </p>
        </div>
      `;
      return;
    }

    const headerTitle = isClosed
      ? "🏆 Pódio Oficial do Evento — 3 Primeiros Colocados"
      : "⏳ Pódio Provisório — 3 Primeiros Colocados (Apuração em Andamento)";

    const rev = state.admin.podiumRevealed || { 1: true, 2: true, 3: true };
    const allHidden = !rev[1] && !rev[2] && !rev[3];

    const headerActionsHtml = `
      <div class="podium-header-actions">
        <button class="podium-btn-action" onclick="window.hideAllWinners()" title="Ocultar nomes e pontuações dos 3 colocados para a apresentação em telão">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>
          <span>Ocultar vencedores</span>
        </button>
        <button class="podium-btn-action ${allHidden ? 'btn-accent' : ''}" onclick="window.revealAllWinners()" title="Revelar todos os 3 colocados de uma só vez">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          <span>Revelar todos</span>
        </button>
      </div>
    `;

    const placesConfig = [
      { place: 1, label: "1º Lugar", trophy: "🥇", cardClass: "podium-card-1" },
      { place: 2, label: "2º Lugar", trophy: "🥈", cardClass: "podium-card-2" },
      { place: 3, label: "3º Lugar", trophy: "🥉", cardClass: "podium-card-3" }
    ];

    let cardsHtml = "";
    placesConfig.forEach(cfg => {
      const p = cfg.place;
      const cand = evaluatedRankings[p - 1] || null;
      const isRevealed = !!rev[p];

      if (!cand) {
        cardsHtml += `
          <div class="podium-card ${cfg.cardClass}" style="opacity: 0.6;">
            <div class="podium-card-header">
              <span class="podium-badge-rank">${cfg.trophy} ${cfg.label}</span>
              <span class="podium-trophy-icon">${cfg.trophy}</span>
            </div>
            <div class="podium-card-body">
              <p style="color: #94A3B8; font-size: 0.85rem; text-align: center;">Posição em aberto (aguardando notas)</p>
            </div>
            <div class="podium-score-row">
              <div>
                <div class="podium-score-val" style="color: #64748B;">---</div>
                <div class="podium-score-lbl">Pontuação Final</div>
              </div>
            </div>
          </div>
        `;
        return;
      }

      const tieBadge = cand.is_tie ? `<span class="badge badge-tie" style="margin-left: 0.35rem;">Empate</span>` : "";

      if (isRevealed) {
        cardsHtml += `
          <div class="podium-card ${cfg.cardClass} is-revealed">
            <div class="podium-card-header">
              <span class="podium-badge-rank">${cfg.trophy} ${cfg.label}</span>
              <button class="podium-hide-btn" onclick="window.hideWinnerPlace(${p})" title="Ocultar esta colocação">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><line x1="2" x2="22" y1="2" y2="22"/></svg>
                <span>Ocultar</span>
              </button>
            </div>
            <div class="podium-card-body">
              <h3 class="podium-cand-name">${cand.name} ${tieBadge}</h3>
              <span class="podium-cand-sub">Inscrição Nº ${cand.number || cand.id} • ${cand.judges_evaluated_count} juízes</span>
            </div>
            <div class="podium-score-row">
              <div>
                <div class="podium-score-val">${cand.final_average_formatted}</div>
                <div class="podium-score-lbl">Pontuação Final</div>
              </div>
              <span class="podium-trophy-icon">${cfg.trophy}</span>
            </div>
          </div>
        `;
      } else {
        cardsHtml += `
          <div class="podium-card ${cfg.cardClass} is-hidden">
            <div class="podium-card-header">
              <span class="podium-badge-rank">${cfg.trophy} ${cfg.label}</span>
              <span class="podium-trophy-icon">${cfg.trophy}</span>
            </div>
            <div class="podium-card-body">
              <div class="podium-secret-box">
                <div class="podium-secret-dots">••••••••••</div>
                <span class="podium-secret-hint">Posição Oculta</span>
              </div>
            </div>
            <div class="podium-score-row">
              <div>
                <div class="podium-score-val" style="letter-spacing: 0.15em;">••••</div>
                <div class="podium-score-lbl">Pontuação Final</div>
              </div>
            </div>
            <div class="podium-card-footer">
              <button class="podium-reveal-btn" onclick="window.revealWinnerPlace(${p})">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                <span>Revelar ${cfg.label}</span>
              </button>
            </div>
          </div>
        `;
      }
    });

    container.innerHTML = `
      <div class="podium-header-bar">
        <div class="podium-header-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/><path d="M4 22h16"/><path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/><path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/><path d="M18 2H6v7a6 6 0 0 0 12 0V2Z"/></svg>
          <span>${headerTitle}</span>
        </div>
        ${headerActionsHtml}
      </div>
      <div class="podium-grid">
        ${cardsHtml}
      </div>
    `;
  }

  function renderWinnerSpotlight(winners, isTie, votingStatus, showProvisional) {
    renderTopThreePodium(state.admin.rankings || [], winners, isTie, votingStatus, showProvisional);
  }

  window.hideAllWinners = function () {
    state.admin.podiumRevealed = { 1: false, 2: false, 3: false };
    renderTopThreePodiumUI();
    showToast("Vencedores ocultados para apresentação.", "info");
  };

  window.revealAllWinners = function () {
    state.admin.podiumRevealed = { 1: true, 2: true, 3: true };
    renderTopThreePodiumUI();
    showToast("Todos os vencedores foram revelados!", "success");
  };

  window.revealWinnerPlace = function (place) {
    if (!state.admin.podiumRevealed) state.admin.podiumRevealed = {};
    state.admin.podiumRevealed[place] = true;
    renderTopThreePodiumUI();
    showToast(`${place}º colocado revelado!`, "success");
  };

  window.hideWinnerPlace = function (place) {
    if (!state.admin.podiumRevealed) state.admin.podiumRevealed = {};
    state.admin.podiumRevealed[place] = false;
    renderTopThreePodiumUI();
  };

  async function loadAdminRankings() {
    const res = await apiRequest("/api/admin/rankings");
    if (!res.success) {
      showToast(res.error || "Erro ao carregar rankings.", "error");
      return;
    }

    state.admin.rankings = res.rankings || [];
    const tbody = document.getElementById("rankingsTableBody");
    tbody.innerHTML = "";

    if (state.admin.rankings.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 2rem;">Nenhum candidato cadastrado.</td></tr>`;
      return;
    }

    state.admin.rankings.forEach(item => {
      const tr = document.createElement("tr");

      // Destaque visual para o pódio
      let rankDisplay = `#${item.rank}`;
      let rankClass = `rank-${item.rank}`;
      if (item.rank === 1) rankDisplay = `🥇 1º`;
      else if (item.rank === 2) rankDisplay = `🥈 2º`;
      else if (item.rank === 3) rankDisplay = `🥉 3º`;

      const tieBadge = item.is_tie ? `<span class="badge badge-tie" style="margin-left: 0.35rem;">Empate</span>` : "";

      // Detalhamento das médias por categoria
      let catAveragesHtml = "";
      if (item.category_averages) {
        Object.values(item.category_averages).forEach(c => {
          catAveragesHtml += `
            <span style="display:inline-block; margin-right: 0.6rem; font-size: 0.8rem; background: var(--slate-100); padding: 0.2rem 0.5rem; border-radius: 4px;">
              <strong>${c.category_name}:</strong> ${c.average_formatted}
            </span>
          `;
        });
      }

      tr.innerHTML = `
        <td><strong class="rank-badge ${rankClass}">${rankDisplay}</strong> ${tieBadge}</td>
        <td>
          <div style="display:flex; align-items:center; gap:0.75rem;">
            <span class="candidate-tag-small">Nº ${item.number || item.id}</span>
            <div>
              <strong>${item.name}</strong>
            </div>
          </div>
        </td>
        <td><span class="avg-pill">${item.final_average_formatted}</span></td>
        <td>${item.total_scores_count} notas</td>
        <td>${item.judges_evaluated_count} juízes</td>
        <td>${catAveragesHtml || '<span style="color:var(--slate-400);">-</span>'}</td>
      `;

      tbody.appendChild(tr);
    });
  }

  async function loadAdminMonitoring() {
    const res = await apiRequest("/api/admin/matrix");
    if (!res.success) {
      showToast(res.error || "Erro ao carregar monitoramento.", "error");
      return;
    }

    state.admin.matrix = res;

    // 1. Progresso individual dos juízes
    const judgesList = document.getElementById("judgesProgressList");
    judgesList.innerHTML = "";

    res.judge_progress.forEach(j => {
      const card = document.createElement("div");
      card.className = "judge-progress-card";
      card.style.marginBottom = "1rem";

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <div>
            <strong>${j.judge_name}</strong> (${j.judge_email})
            ${j.is_finished ? '<span class="badge badge-emerald" style="margin-left: 0.5rem;">100% Concluído</span>' : '<span class="badge badge-amber" style="margin-left: 0.5rem;">Em Andamento</span>'}
          </div>
          <span style="font-family: var(--font-mono); font-weight: 700; color: var(--primary);">
            ${j.completed_candidates} de ${j.total_candidates} (${j.percentage}%)
          </span>
        </div>
        <div class="progress-bar-bg">
          <div class="progress-bar-fill" style="width: ${j.percentage}%;"></div>
        </div>
      `;

      judgesList.appendChild(card);
    });

    // 2. Matriz completa de notas
    renderScoreMatrix(res);
  }

  function renderScoreMatrix(data) {
    const container = document.getElementById("matrixContainer");
    if (!data.candidates || data.candidates.length === 0) {
      container.innerHTML = `<p style="padding: 1.5rem; text-align: center;">Nenhum candidato cadastrado.</p>`;
      return;
    }

    let headerCols = "<th>Candidato</th>";
    data.categories.forEach(cat => {
      headerCols += `<th>${cat.name}</th>`;
    });

    let bodyRows = "";
    data.candidates.forEach(cand => {
      let catCells = "";
      data.categories.forEach(cat => {
        const scoresObj = (data.matrix[cand.id] && data.matrix[cand.id][cat.id]) || {};
        const scoresList = Object.values(scoresObj);
        let cellText = "-";
        if (scoresList.length > 0) {
          const avg = (scoresList.reduce((a, b) => a + b, 0) / scoresList.length).toFixed(2);
          cellText = `<strong>${avg}</strong> <span style="font-size:0.75rem; color:var(--slate-500);">(${scoresList.join(", ")})</span>`;
        }
        catCells += `<td>${cellText}</td>`;
      });

      bodyRows += `
        <tr>
          <td>
            <strong>${cand.name}</strong>
            <span style="display:block; font-size:0.75rem; color:var(--slate-500);">Nº ${cand.number || cand.id}</span>
          </td>
          ${catCells}
        </tr>
      `;
    });

    container.innerHTML = `
      <table class="data-table">
        <thead><tr>${headerCols}</tr></thead>
        <tbody>${bodyRows}</tbody>
      </table>
    `;
  }

  // --- CRUD: Candidatos ---
  async function loadAdminCandidates() {
    const res = await apiRequest("/api/admin/candidates");
    if (!res.success) return;

    state.admin.candidates = res.candidates || [];
    if (res.active_campaign) {
      state.activeCampaign = res.active_campaign;
      const campNameEl = document.getElementById("candidatesCampaignName");
      if (campNameEl) campNameEl.textContent = res.active_campaign.name;
      const dangerCampEl = document.getElementById("dangerCampaignName");
      if (dangerCampEl) dangerCampEl.textContent = res.active_campaign.name;
      updateHeaderUI();
    }

    const tbody = document.getElementById("candidatesTableBody");
    tbody.innerHTML = "";

    if (state.admin.candidates.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2.5rem 1rem;">
            Nenhum candidato cadastrado nesta campanha até o momento.<br>
            <span style="font-size: 0.85rem;">Utilize o botão "Novo Candidato" ou importe múltiplos candidatos via arquivo .txt.</span>
          </td>
        </tr>
      `;
      return;
    }

    state.admin.candidates.forEach(c => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong class="candidate-tag-small">Nº ${c.number || c.id}</strong></td>
        <td><strong>${c.name}</strong></td>
        <td style="max-width: 350px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${c.description || "-"}</td>
        <td>
          <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-xs btn-outline" onclick='window.editCandidate(${JSON.stringify(c)})'>Editar</button>
            <button class="btn btn-xs btn-danger" onclick="window.deleteCandidate(${c.id}, '${c.name.replace(/'/g, "\\'")}')">Excluir</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  window.openCandidateModal = function () {
    document.getElementById("modalCandidateTitle").textContent = "Novo Candidato";
    document.getElementById("candidateFormId").value = "";
    document.getElementById("candidateFormName").value = "";
    document.getElementById("candidateFormDesc").value = "";
    document.getElementById("modalCandidate").classList.add("active");
  };

  window.editCandidate = function (cand) {
    document.getElementById("modalCandidateTitle").textContent = "Editar Candidato";
    document.getElementById("candidateFormId").value = cand.id;
    document.getElementById("candidateFormName").value = cand.name;
    document.getElementById("candidateFormDesc").value = cand.description || "";
    document.getElementById("modalCandidate").classList.add("active");
  };

  window.closeCandidateModal = function () {
    document.getElementById("modalCandidate").classList.remove("active");
  };

  async function handleCandidateFormSubmit(e) {
    e.preventDefault();
    const id = document.getElementById("candidateFormId").value;
    const name = document.getElementById("candidateFormName").value.trim();
    const description = document.getElementById("candidateFormDesc").value.trim();

    const url = id ? `/api/admin/candidates/${id}` : "/api/admin/candidates";
    const method = id ? "PUT" : "POST";

    const res = await apiRequest(url, {
      method,
      body: { name, description }
    });

    if (res.success) {
      showToast(res.message || "Candidato salvo com sucesso!", "success");
      closeCandidateModal();
      loadAdminCandidates();
      loadAdminDashboard();
    } else {
      showToast(res.error || "Erro ao salvar candidato.", "error");
    }
  }

  // --- Importação em Lote (.txt) ---
  window.openBulkCandidateModal = function () {
    const fileInput = document.getElementById("bulkCandidateFileInput");
    if (fileInput) fileInput.value = "";
    const textarea = document.getElementById("bulkCandidateText");
    if (textarea) textarea.value = "";
    window.updateBulkCandidatePreview();
    document.getElementById("modalBulkCandidate").classList.add("active");
  };

  window.closeBulkCandidateModal = function () {
    document.getElementById("modalBulkCandidate").classList.remove("active");
  };

  window.handleBulkCandidateFileSelected = function (e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (evt) {
      const content = evt.target.result;
      document.getElementById("bulkCandidateText").value = content;
      window.updateBulkCandidatePreview();
    };
    reader.readAsText(file, "UTF-8");
  };

  window.updateBulkCandidatePreview = function () {
    const textarea = document.getElementById("bulkCandidateText");
    const text = textarea ? textarea.value : "";
    const lines = text.split("\n").map(l => l.trim()).filter(l => l.length > 0);
    const badge = document.getElementById("bulkCandidatesCount");
    if (badge) {
      badge.textContent = `${lines.length} candidato${lines.length === 1 ? '' : 's'} identificado${lines.length === 1 ? '' : 's'}`;
    }
    const btn = document.getElementById("btnSubmitBulkCandidate");
    if (btn) {
      btn.disabled = lines.length === 0;
    }
  };

  window.handleBulkCandidateSubmit = async function (e) {
    e.preventDefault();
    const textarea = document.getElementById("bulkCandidateText");
    const text = textarea ? textarea.value : "";
    const names = text.split("\n").map(l => l.trim()).filter(l => l.length > 0);

    if (names.length === 0) {
      showToast("Nenhum candidato informado no arquivo ou texto.", "warning");
      return;
    }

    const res = await apiRequest("/api/admin/candidates/bulk-import", {
      method: "POST",
      body: { names }
    });

    if (res.success) {
      showToast(res.message || `${names.length} candidatos importados com sucesso!`, "success");
      closeBulkCandidateModal();
      loadAdminCandidates();
      loadAdminDashboard();
    } else {
      showToast(res.error || "Erro ao importar candidatos.", "error");
    }
  };

  window.deleteCandidate = async function (id, name) {
    if (!confirm(`Deseja realmente excluir o candidato "${name}"? Todas as notas associadas serão removidas.`)) return;

    const res = await apiRequest(`/api/admin/candidates/${id}`, { method: "DELETE" });
    if (res.success) {
      showToast(res.message || "Candidato excluído.", "success");
      loadAdminCandidates();
      loadAdminDashboard();
    } else {
      showToast(res.error || "Erro ao excluir candidato.", "error");
    }
  };

  // --- CRUD: Juízes ---
  async function loadAdminJudges() {
    const res = await apiRequest("/api/admin/judges");
    if (!res.success) return;

    state.admin.judges = res.judges || [];
    const tbody = document.getElementById("judgesTableBody");
    tbody.innerHTML = "";

    state.admin.judges.forEach(j => {
      const tr = document.createElement("tr");
      const judgeJson = JSON.stringify(j).replace(/'/g, "&#39;");
      tr.innerHTML = `
        <td><strong>${j.name}</strong></td>
        <td>${j.email}</td>
        <td><span class="badge ${j.active ? 'badge-emerald' : 'badge-slate'}">${j.active ? 'Ativo' : 'Inativo'}</span></td>
        <td>${new Date(j.created_at).toLocaleDateString("pt-BR")}</td>
        <td>
          <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
            <button class="btn btn-xs btn-outline" onclick='window.editJudge(${judgeJson})'>Editar</button>
            <button class="btn btn-xs btn-outline" onclick='window.openResetJudgePasswordModal(${judgeJson})' title="Definir nova senha para este juiz">🔑 Resetar Senha</button>
            <button class="btn btn-xs btn-danger" onclick="window.deleteJudge(${j.id}, '${j.name.replace(/'/g, "\\'")}')">Excluir</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  window.openResetJudgePasswordModal = function (judge) {
    document.getElementById("resetJudgeId").value = judge.id;
    document.getElementById("resetJudgeName").textContent = judge.name;
    document.getElementById("resetJudgeEmail").textContent = judge.email;
    document.getElementById("resetJudgeNewPassword").value = "";
    document.getElementById("modalResetJudgePassword").classList.add("active");
  };

  window.closeResetJudgePasswordModal = function () {
    document.getElementById("modalResetJudgePassword").classList.remove("active");
  };

  window.generateRandomJudgePassword = function () {
    const chars = "abcdefghjkmnpqrstuvwxyz23456789";
    let pwd = "juiz@";
    for (let i = 0; i < 4; i++) {
      pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById("resetJudgeNewPassword").value = pwd;
  };

  window.handleResetJudgePasswordSubmit = async function (e) {
    e.preventDefault();
    const id = document.getElementById("resetJudgeId").value;
    const password = document.getElementById("resetJudgeNewPassword").value.trim();

    if (!password) {
      showToast("Por favor, digite a nova senha.", "error");
      return;
    }

    const res = await apiRequest(`/api/admin/judges/${id}/reset-password`, {
      method: "POST",
      body: { password }
    });

    if (res.success) {
      showToast(res.message || "Senha redefinida com sucesso!", "success");
      closeResetJudgePasswordModal();
    } else {
      showToast(res.error || "Erro ao redefinir senha.", "error");
    }
  };

  window.openJudgeModal = function () {
    document.getElementById("modalJudgeTitle").textContent = "Novo Juiz";
    document.getElementById("judgeFormId").value = "";
    document.getElementById("judgeFormName").value = "";
    document.getElementById("judgeFormEmail").value = "";
    document.getElementById("judgeFormPassword").value = "";
    document.getElementById("judgeFormPasswordLabel").textContent = "Senha de Acesso *";
    document.getElementById("judgeFormPasswordHint").style.display = "none";
    document.getElementById("modalJudge").classList.add("active");
  };

  window.editJudge = function (judge) {
    document.getElementById("modalJudgeTitle").textContent = "Editar Juiz";
    document.getElementById("judgeFormId").value = judge.id;
    document.getElementById("judgeFormName").value = judge.name;
    document.getElementById("judgeFormEmail").value = judge.email;
    document.getElementById("judgeFormPassword").value = "";
    document.getElementById("judgeFormPasswordLabel").textContent = "Nova Senha (Opcional)";
    document.getElementById("judgeFormPasswordHint").style.display = "block";
    document.getElementById("modalJudge").classList.add("active");
  };

  window.closeJudgeModal = function () {
    document.getElementById("modalJudge").classList.remove("active");
  };

  async function handleJudgeFormSubmit(e) {
    e.preventDefault();
    const id = document.getElementById("judgeFormId").value;
    const name = document.getElementById("judgeFormName").value.trim();
    const email = document.getElementById("judgeFormEmail").value.trim();
    const password = document.getElementById("judgeFormPassword").value;

    if (!id && !password) {
      showToast("A senha é obrigatória para cadastrar um novo juiz.", "error");
      return;
    }

    const url = id ? `/api/admin/judges/${id}` : "/api/admin/judges";
    const method = id ? "PUT" : "POST";

    const body = { name, email };
    if (password) body.password = password;

    const res = await apiRequest(url, { method, body });
    if (res.success) {
      showToast(res.message || "Juiz salvo com sucesso!", "success");
      closeJudgeModal();
      loadAdminJudges();
    } else {
      showToast(res.error || "Erro ao salvar juiz.", "error");
    }
  }

  window.deleteJudge = async function (id, name) {
    if (!confirm(`Deseja realmente excluir o juiz "${name}"?`)) return;

    const res = await apiRequest(`/api/admin/judges/${id}`, { method: "DELETE" });
    if (res.success) {
      showToast(res.message || "Juiz excluído.", "success");
      loadAdminJudges();
    } else {
      showToast(res.error || "Erro ao excluir juiz.", "error");
    }
  };

  // --- CRUD: Categorias ---
  async function loadAdminCategories() {
    const res = await apiRequest("/api/admin/categories");
    if (!res.success) return;

    state.admin.categories = res.categories || [];
    const tbody = document.getElementById("categoriesTableBody");
    tbody.innerHTML = "";

    state.admin.categories.forEach(cat => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>#${cat.display_order}</strong></td>
        <td><strong>${cat.name}</strong></td>
        <td>${cat.description || "-"}</td>
        <td><span class="badge ${cat.active ? 'badge-emerald' : 'badge-slate'}">${cat.active ? 'Ativa' : 'Inativa'}</span></td>
        <td>
          <div style="display:flex; gap:0.5rem;">
            <button class="btn btn-xs btn-outline" onclick='window.editCategory(${JSON.stringify(cat)})'>Editar</button>
            <button class="btn btn-xs btn-danger" onclick="window.deleteCategory(${cat.id}, '${cat.name.replace(/'/g, "\\'")}')">Excluir</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  window.openCategoryModal = function () {
    document.getElementById("modalCategoryTitle").textContent = "Nova Categoria de Avaliação";
    document.getElementById("categoryFormId").value = "";
    document.getElementById("categoryFormName").value = "";
    document.getElementById("categoryFormDesc").value = "";
    document.getElementById("categoryFormOrder").value = (state.admin.categories.length + 1);
    document.getElementById("modalCategory").classList.add("active");
  };

  window.editCategory = function (cat) {
    document.getElementById("modalCategoryTitle").textContent = "Editar Categoria";
    document.getElementById("categoryFormId").value = cat.id;
    document.getElementById("categoryFormName").value = cat.name;
    document.getElementById("categoryFormDesc").value = cat.description || "";
    document.getElementById("categoryFormOrder").value = cat.display_order || 1;
    document.getElementById("modalCategory").classList.add("active");
  };

  window.closeCategoryModal = function () {
    document.getElementById("modalCategory").classList.remove("active");
  };

  async function handleCategoryFormSubmit(e) {
    e.preventDefault();
    const id = document.getElementById("categoryFormId").value;
    const name = document.getElementById("categoryFormName").value.trim();
    const description = document.getElementById("categoryFormDesc").value.trim();
    const display_order = parseInt(document.getElementById("categoryFormOrder").value, 10) || 1;

    const url = id ? `/api/admin/categories/${id}` : "/api/admin/categories";
    const method = id ? "PUT" : "POST";

    const res = await apiRequest(url, {
      method,
      body: { name, description, display_order }
    });

    if (res.success) {
      showToast(res.message || "Categoria salva com sucesso!", "success");
      closeCategoryModal();
      loadAdminCategories();
    } else {
      showToast(res.error || "Erro ao salvar categoria.", "error");
    }
  }

  window.deleteCategory = async function (id, name) {
    if (!confirm(`Deseja excluir a categoria "${name}"? Se houver notas associadas, ela será desativada para preservar os resultados.`)) return;

    const res = await apiRequest(`/api/admin/categories/${id}`, { method: "DELETE" });
    if (res.success) {
      showToast(res.message || "Categoria processada.", "success");
      loadAdminCategories();
    } else {
      showToast(res.error || "Erro ao excluir categoria.", "error");
    }
  };

  // --- Governança, Configurações e Auditoria ---
  async function loadAdminSettings() {
    const res = await apiRequest("/api/admin/settings");
    if (!res.success) return;

    const settings = res.settings;
    state.admin.settings = settings;

    // Radios de status
    const statusVal = settings.voting_status || "OPEN";
    const radio = document.querySelector(`input[name="eventVotingStatus"][value="${statusVal}"]`);
    if (radio) radio.checked = true;

    // Toggles
    document.getElementById("settingAllowCorrections").checked = settings.allow_corrections === "true";
    document.getElementById("settingShowProvisionalWinner").checked = settings.show_provisional_winner === "true";
    document.getElementById("settingPublishResults").checked = settings.public_results_published === "true";
    document.getElementById("settingEventName").value = settings.event_name || "";

    loadAdminCampaigns();
    loadAdminAuditLogs();
  }

  // --- Gerenciamento de Campanhas ---
  async function loadAdminCampaigns() {
    const res = await apiRequest("/api/admin/campaigns");
    if (!res.success) return;

    const select = document.getElementById("campaignSelect");
    if (select) {
      select.innerHTML = "";
      (res.campaigns || []).forEach(c => {
        const opt = document.createElement("option");
        opt.value = c.id;
        opt.textContent = `${c.name} (${c.candidates_count || 0} candidatos)`;
        if (c.id === res.active_campaign_id) {
          opt.selected = true;
          state.activeCampaign = c;
        }
        select.appendChild(opt);
      });
    }

    const activeCamp = (res.campaigns || []).find(c => c.id === res.active_campaign_id);
    if (activeCamp) {
      state.activeCampaign = activeCamp;
      const dangerNameEl = document.getElementById("dangerCampaignName");
      if (dangerNameEl) dangerNameEl.textContent = activeCamp.name;

      const candCampNameEl = document.getElementById("candidatesCampaignName");
      if (candCampNameEl) candCampNameEl.textContent = activeCamp.name;
    }

    updateHeaderUI();
  }

  window.switchCampaign = async function (campaignId) {
    if (!campaignId) return;
    const res = await apiRequest(`/api/admin/campaigns/${campaignId}/activate`, { method: "POST" });
    if (res.success) {
      showToast(res.message, "success");
      await loadAdminCampaigns();
      await loadAdminCandidates();
      await loadAdminDashboard();
      if (state.admin.currentTab === "tabRankings") await loadAdminRankings();
      if (state.admin.currentTab === "tabMonitoring") await loadEvaluationMatrix();
    } else {
      showToast(res.error || "Erro ao alternar campanha.", "error");
    }
  };

  window.openNewCampaignModal = function () {
    document.getElementById("campaignFormName").value = "";
    document.getElementById("campaignFormDesc").value = "";
    document.getElementById("modalNewCampaign").classList.add("active");
  };

  window.closeNewCampaignModal = function () {
    document.getElementById("modalNewCampaign").classList.remove("active");
  };

  window.handleNewCampaignSubmit = async function (e) {
    e.preventDefault();
    const name = document.getElementById("campaignFormName").value.trim();
    const description = document.getElementById("campaignFormDesc").value.trim();

    if (!name) {
      showToast("Informe o nome da campanha.", "warning");
      return;
    }

    const res = await apiRequest("/api/admin/campaigns", {
      method: "POST",
      body: { name, description }
    });

    if (res.success) {
      showToast(res.message, "success");
      closeNewCampaignModal();
      await loadAdminCampaigns();
      await loadAdminCandidates();
      await loadAdminDashboard();
      await loadAdminSettings();
      if (state.admin.currentTab === "tabRankings") await loadAdminRankings();
      if (state.admin.currentTab === "tabMonitoring") await loadEvaluationMatrix();
    } else {
      showToast(res.error || "Erro ao criar campanha.", "error");
    }
  };

  window.clearCurrentCampaignCandidates = async function () {
    const activeCampName = state.activeCampaign ? state.activeCampaign.name : "atual";
    const confirmMsg = `ATENÇÃO: Deseja realmente excluir TODOS os candidatos e todas as notas da campanha "${activeCampName}"?\n\nEsta ação é irreversível e zerará a votação desta campanha!`;
    if (!confirm(confirmMsg)) return;

    const res = await apiRequest("/api/admin/candidates/clear-current-campaign", { method: "DELETE" });
    if (res.success) {
      showToast(res.message, "success");
      await loadAdminCandidates();
      await loadAdminDashboard();
      await loadAdminCampaigns();
      if (state.admin.currentTab === "tabRankings") await loadAdminRankings();
      if (state.admin.currentTab === "tabMonitoring") await loadEvaluationMatrix();
    } else {
      showToast(res.error || "Erro ao limpar candidatos da campanha.", "error");
    }
  };

  async function saveAdminSettings() {
    const selectedRadio = document.querySelector('input[name="eventVotingStatus"]:checked');
    const voting_status = selectedRadio ? selectedRadio.value : "OPEN";
    const allow_corrections = document.getElementById("settingAllowCorrections").checked ? "true" : "false";
    const show_provisional_winner = document.getElementById("settingShowProvisionalWinner").checked ? "true" : "false";
    const public_results_published = document.getElementById("settingPublishResults").checked ? "true" : "false";
    const event_name = document.getElementById("settingEventName").value.trim() || "Festival de Talentos";

    const res = await apiRequest("/api/admin/settings", {
      method: "PUT",
      body: {
        voting_status,
        allow_corrections,
        show_provisional_winner,
        public_results_published,
        event_name
      }
    });

    if (res.success) {
      showToast("Configurações salvas com sucesso!", "success");
      state.eventInfo = { ...state.eventInfo, ...res.settings };
      updateHeaderUI();
      loadAdminSettings();
    } else {
      showToast(res.error || "Erro ao salvar configurações.", "error");
    }
  }

  async function loadAdminAuditLogs() {
    const res = await apiRequest("/api/admin/audit-logs");
    if (!res.success) return;

    const tbody = document.getElementById("auditLogsTableBody");
    tbody.innerHTML = "";

    (res.logs || []).forEach(log => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="font-family: var(--font-mono); font-size: 0.8rem;">${new Date(log.created_at).toLocaleString("pt-BR")}</td>
        <td><strong>${log.user_name || "Sistema"}</strong></td>
        <td><span class="badge badge-outline">${log.action}</span></td>
        <td style="font-size: 0.85rem;">${log.details || "-"}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // =========================================================================
  // Controle de Identidade Visual e Tema Korporate (Light / Dark)
  // =========================================================================

  function getActiveTheme() {
    return document.documentElement.getAttribute("data-theme") || localStorage.getItem("kor_theme") || "light";
  }

  function applyTheme(theme) {
    const validTheme = theme === "dark" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", validTheme);
    localStorage.setItem("kor_theme", validTheme);

    const isDark = validTheme === "dark";

    // Atualiza botão do Header
    const headerIcon = document.getElementById("themeToggleIconHeader");
    const headerBtn = document.getElementById("btnThemeToggleHeader");
    if (headerIcon) {
      headerIcon.textContent = isDark ? "☀️" : "🌙";
    }
    if (headerBtn) {
      headerBtn.setAttribute("title", isDark ? "Mudar para Modo Claro" : "Mudar para Modo Escuro");
    }

    // Atualiza botão do Card de Controle de Eventos
    const cardIcon = document.getElementById("themeToggleCardIcon");
    const cardText = document.getElementById("themeToggleCardText");
    if (cardIcon) {
      cardIcon.textContent = isDark ? "☀️" : "🌙";
    }
    if (cardText) {
      cardText.textContent = isDark ? "Alternar para Modo Claro" : "Alternar para Modo Escuro";
    }
  }

  function toggleTheme() {
    const current = getActiveTheme();
    const next = current === "dark" ? "light" : "dark";
    applyTheme(next);
    showToast(next === "dark" ? "Modo Escuro Korporate ativado." : "Modo Claro Korporate ativado.", "info");
  }

  function resetThemeDefault() {
    applyTheme("light");
    showToast("Identidade visual padrão restaurada com sucesso.", "success");
  }

  // =========================================================================
  // Inicialização e Event Listeners
  // =========================================================================

  function init() {
    // Formulário de Login
    const formLogin = document.getElementById("formLogin");
    if (formLogin) formLogin.addEventListener("submit", handleLoginSubmit);

    // Botão de Logout
    const btnLogout = document.getElementById("btnLogout");
    if (btnLogout) btnLogout.addEventListener("click", logout);

    // Navegação e Filtros do Juiz
    const btnBack = document.getElementById("btnBackToJudgeList");
    if (btnBack) btnBack.addEventListener("click", () => switchView("viewJudge"));

    const btnConfirm = document.getElementById("btnConfirmEvaluation");
    if (btnConfirm) btnConfirm.addEventListener("click", submitJudgeEvaluation);

    // Filtros de Candidatos no Juiz
    document.querySelectorAll(".pill").forEach(pill => {
      pill.addEventListener("click", () => {
        document.querySelectorAll(".pill").forEach(p => p.classList.remove("active"));
        pill.classList.add("active");
        state.judge.filter = pill.getAttribute("data-filter");
        renderJudgeCandidatesGrid();
      });
    });

    const searchInput = document.getElementById("judgeSearchCandidate");
    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        state.judge.searchQuery = e.target.value;
        renderJudgeCandidatesGrid();
      });
    }

    // Formulários Modais do Admin
    const formCand = document.getElementById("formCandidate");
    if (formCand) formCand.addEventListener("submit", handleCandidateFormSubmit);

    const formJudge = document.getElementById("formJudge");
    if (formJudge) formJudge.addEventListener("submit", handleJudgeFormSubmit);

    const formCat = document.getElementById("formCategory");
    if (formCat) formCat.addEventListener("submit", handleCategoryFormSubmit);

    // Salvar Configurações
    const btnSettings = document.getElementById("btnSaveSettings");
    if (btnSettings) btnSettings.addEventListener("click", saveAdminSettings);

    // Exportar funções necessárias no escopo global
    window.switchView = switchView;
    window.loadAdminDashboard = loadAdminDashboard;
    window.loadAdminRankings = loadAdminRankings;
    window.renewSession = renewSession;
    window.closeSessionTimeoutModal = closeSessionTimeoutModal;
    window.toggleTheme = toggleTheme;
    window.resetThemeDefault = resetThemeDefault;
    window.applyTheme = applyTheme;

    // Inicializar tema Korporate
    applyTheme(localStorage.getItem("kor_theme") || "light");

    // Inicializar gerenciamento centralizado de sessão e inatividade
    initSessionManager();

    // Verificar sessão existente
    checkAuthSession();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
