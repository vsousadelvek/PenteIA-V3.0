"""
QA Visual Automatizado — PenteIA v4.0
Selenium + Chrome headless, screenshots de todas as páginas,
detecção de erros JS, console errors, elementos quebrados.
"""
import os, sys, time, json, re
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from pathlib import Path
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException, NoSuchElementException, WebDriverException
)
from webdriver_manager.chrome import ChromeDriverManager

BASE    = "http://localhost:5173"
API     = "http://localhost:8000"
OUT_DIR = Path("E:/cyber/PenteIA-V4.0/qa_screenshots")
OUT_DIR.mkdir(parents=True, exist_ok=True)

CREDS = {"username": "admin", "password": "admin123"}

# ── Todas as rotas para testar ─────────────────────────────────────────────────
PAGES = [
    # (slug, path, precisa_login, descricao)
    ("login",          "/login",          False, "Tela de Login"),
    ("pricing",        "/pricing",        False, "Página de Preços"),
    ("dashboard",      "/dashboard",      True,  "Dashboard"),
    ("recon",          "/recon",          True,  "Reconhecimento"),
    ("cloud",          "/cloud",          True,  "Cloud Recon"),
    ("cloud-identity", "/cloud-identity", True,  "Cloud Identity (AWS/Entra)"),
    ("bas",            "/bas",            True,  "BAS / MITRE ATT&CK"),
    ("attck-matrix",   "/attck-matrix",   True,  "ATT&CK Matrix"),
    ("vulndb",         "/vulndb",         True,  "VulnDB"),
    ("ddos",           "/ddos",           True,  "DDoS Testing"),
    ("campaign",       "/campaign",       True,  "Campanha DDoS"),
    ("c2",             "/c2",             True,  "C2 Framework"),
    ("agents",         "/agents",         True,  "Agentes"),
    ("modules",        "/modules",        True,  "Módulos"),
    ("evasion",        "/evasion",        True,  "Evasão & Payloads"),
    ("phishing",       "/phishing",       True,  "Phishing Simulation"),
    ("soc-validation", "/soc-validation", True,  "SOC Validation"),
    ("remediation",    "/remediation",    True,  "Remediation Tracker"),
    ("integrations",   "/integrations",   True,  "Integrations (Sentinel/Wazuh)"),
    ("ai",             "/ai",             True,  "IA & Machine Learning"),
    ("operations",     "/operations",     True,  "Operações"),
    ("reporting",      "/reporting",      True,  "Relatórios"),
    ("admin",          "/admin",          True,  "Admin Panel"),
]

# ── Resultados ─────────────────────────────────────────────────────────────────
results = []

def log(msg): print(msg, flush=True)


def make_driver():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--window-size=1440,900")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--log-level=3")
    opts.add_experimental_option("excludeSwitches", ["enable-logging"])
    # Capturar console JS
    opts.set_capability("goog:loggingPrefs", {"browser": "ALL"})
    svc = Service(ChromeDriverManager().install(), log_output=os.devnull)
    return webdriver.Chrome(service=svc, options=opts)


def wait_page_stable(driver, timeout=12):
    """Aguarda a página carregar e React renderizar."""
    try:
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
    except TimeoutException:
        pass
    # Aguarda spinner sumir (PageLoader do App.jsx)
    try:
        WebDriverWait(driver, 8).until_not(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".animate-spin"))
        )
    except TimeoutException:
        pass
    time.sleep(0.8)  # buffer para re-renders finais


def get_console_errors(driver):
    try:
        logs = driver.get_log("browser")
        return [l for l in logs if l["level"] in ("SEVERE", "WARNING")]
    except Exception:
        return []


def check_page_health(driver, slug):
    """Verifica indicadores de erro na página."""
    issues = []
    body_text = driver.find_element(By.TAG_NAME, "body").text.lower()

    # Erros React
    if "something went wrong" in body_text or "errorboundary" in body_text.lower():
        issues.append("ErrorBoundary ativado")
    if "cannot read" in body_text or "typeerror" in body_text or "referenceerror" in body_text:
        issues.append("Erro JS visível na página")

    # Página em branco (< 100 chars de texto)
    if len(body_text.strip()) < 100 and slug not in ("login",):
        issues.append(f"Página com pouco conteúdo ({len(body_text.strip())} chars)")

    # Imagens quebradas
    broken_imgs = driver.execute_script("""
        return Array.from(document.images)
            .filter(i => !i.complete || i.naturalWidth === 0)
            .map(i => i.src).slice(0,3)
    """)
    if broken_imgs:
        issues.append(f"Imagens quebradas: {broken_imgs}")

    # Console errors
    console_errs = get_console_errors(driver)
    severe = [e["message"][:120] for e in console_errs if e["level"] == "SEVERE"]
    if severe:
        issues.append(f"Console SEVERE: {severe[:3]}")

    # Verificar se há elementos de conteúdo (cards, tabelas, forms)
    content_els = driver.execute_script("""
        return document.querySelectorAll(
            '.card-dark, table, form, [class*="card"], [class*="grid"], main > div'
        ).length
    """)

    return issues, content_els, console_errs


def do_login(driver):
    driver.get(f"{BASE}/login")
    wait_page_stable(driver)
    try:
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='text'], input[placeholder*='usuario']")))
        user_field = driver.find_element(By.CSS_SELECTOR, "input[type='text'], input[autocomplete='username']")
        pass_field = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        user_field.clear(); user_field.send_keys(CREDS["username"])
        pass_field.clear(); pass_field.send_keys(CREDS["password"])
        btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        btn.click()
        WebDriverWait(driver, 12).until(EC.url_contains("/dashboard"))
        wait_page_stable(driver)
        log("  ✓ Login realizado com sucesso")
        return True
    except Exception as e:
        log(f"  ✗ Login falhou: {e}")
        # Tenta criar conta admin se não existir
        try:
            toggle = driver.find_element(By.XPATH, "//*[contains(text(),'Solicitar') or contains(text(),'criar')]")
            toggle.click()
            time.sleep(0.5)
            # preenche registro
            fields = driver.find_elements(By.CSS_SELECTOR, "input")
            for f in fields:
                ac = f.get_attribute("autocomplete") or ""
                ph = f.get_attribute("placeholder") or ""
                if "username" in ac or "usuario" in ph.lower():
                    f.clear(); f.send_keys(CREDS["username"])
                elif "email" in ac or "email" in ph.lower():
                    f.clear(); f.send_keys("admin@penteia.local")
                elif "password" in ac or "senha" in ph.lower() or f.get_attribute("type") == "password":
                    f.clear(); f.send_keys(CREDS["password"])
            btn = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
            btn.click()
            time.sleep(3)
            log("  ✓ Conta criada, tentando login novamente...")
            return do_login(driver)
        except Exception as e2:
            log(f"  ✗ Registro falhou: {e2}")
            return False


def screenshot(driver, slug, suffix=""):
    fname = f"{slug}{suffix}.png"
    path  = OUT_DIR / fname
    driver.save_screenshot(str(path))
    return str(path)


def test_page(driver, slug, path, needs_login, desc):
    log(f"\n{'='*60}")
    log(f"  Testando: {desc}  ({path})")

    result = {
        "slug": slug, "path": path, "desc": desc,
        "status": "ok", "issues": [], "screenshots": [],
        "content_elements": 0, "console_errors": 0,
        "load_time_ms": 0,
    }

    t0 = time.time()
    try:
        driver.get(f"{BASE}{path}")
        wait_page_stable(driver)
        result["load_time_ms"] = int((time.time() - t0) * 1000)

        # Screenshot inicial
        ss = screenshot(driver, slug, "_01_load")
        result["screenshots"].append(ss)
        log(f"  → Screenshot: {ss}")

        # Health check
        issues, content_els, console_logs = check_page_health(driver, slug)
        result["issues"] = issues
        result["content_elements"] = content_els
        result["console_errors"] = len([l for l in console_logs if l["level"] == "SEVERE"])

        if issues:
            result["status"] = "warning"
            for i in issues:
                log(f"  ⚠  {i}")
        else:
            log(f"  ✓ Sem erros detectados ({content_els} elementos de conteúdo)")

        log(f"  ↳ Load time: {result['load_time_ms']}ms")

        # Scroll para capturar conteúdo abaixo da dobra
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight / 2)")
        time.sleep(0.4)
        ss2 = screenshot(driver, slug, "_02_scroll")
        result["screenshots"].append(ss2)

        # Teste de interações específicas por página
        _test_interactions(driver, slug, result)

    except Exception as e:
        result["status"] = "error"
        result["issues"].append(f"Exceção: {str(e)[:200]}")
        log(f"  ✗ Erro: {e}")
        try:
            ss_err = screenshot(driver, slug, "_ERROR")
            result["screenshots"].append(ss_err)
        except Exception:
            pass

    return result


def _test_interactions(driver, slug, result):
    """Testa interações específicas em cada página."""
    try:
        if slug == "dashboard":
            # Verifica cards de métricas
            cards = driver.find_elements(By.CSS_SELECTOR, "[class*='card'], [class*='grid'] > div")
            log(f"  → Dashboard: {len(cards)} cards/elementos")

        elif slug == "bas":
            # Verifica se há botão de nova simulação
            btns = driver.find_elements(By.XPATH, "//*[contains(text(),'Nova') or contains(text(),'Simul')]")
            log(f"  → BAS: {len(btns)} botões de ação")

        elif slug == "ai":
            # Verifica as 5 abas
            tabs = driver.find_elements(By.XPATH, "//*[contains(text(),'Analisar') or contains(text(),'Chat') or contains(text(),'Pentest') or contains(text(),'IOC') or contains(text(),'Cadeia')]")
            log(f"  → AI: {len(tabs)} abas encontradas")
            if tabs:
                # Clica em Chat
                for tab in tabs:
                    if "Chat" in tab.text:
                        tab.click()
                        time.sleep(0.8)
                        screenshot(driver, slug, "_03_chat_tab")
                        break
                # Clica em IOC
                for tab in tabs:
                    if "IOC" in tab.text:
                        tab.click()
                        time.sleep(0.8)
                        screenshot(driver, slug, "_04_ioc_tab")
                        break

        elif slug == "attck-matrix":
            # Verifica grade de táticas
            cells = driver.find_elements(By.CSS_SELECTOR, "[class*='grid'] div, td, th")
            log(f"  → ATT&CK Matrix: {len(cells)} células")

        elif slug == "phishing":
            # Verifica templates
            templates = driver.find_elements(By.XPATH, "//*[contains(text(),'template') or contains(text(),'Template') or contains(text(),'campanha')]")
            log(f"  → Phishing: {len(templates)} referências de templates")

        elif slug == "integrations":
            # Verifica painéis Sentinel e Wazuh
            panels = driver.find_elements(By.XPATH, "//*[contains(text(),'Sentinel') or contains(text(),'Wazuh')]")
            log(f"  → Integrations: {len(panels)} referências de integração")

        elif slug == "remediation":
            # Verifica colunas do Kanban
            cols = driver.find_elements(By.XPATH, "//*[contains(text(),'Open') or contains(text(),'In Progress') or contains(text(),'Resolved')]")
            log(f"  → Remediation: {len(cols)} colunas Kanban encontradas")

        elif slug == "soc-validation":
            btns = driver.find_elements(By.XPATH, "//*[contains(text(),'Validar') or contains(text(),'SIEM')]")
            log(f"  → SOC Validation: {len(btns)} elementos de validação")

        elif slug == "cloud-identity":
            # Verifica painéis AWS e Entra
            panels = driver.find_elements(By.XPATH, "//*[contains(text(),'AWS') or contains(text(),'Entra') or contains(text(),'Azure')]")
            log(f"  → Cloud Identity: {len(panels)} painéis cloud")

        elif slug in ("login", "pricing"):
            # Verifica formulário / cards
            forms = driver.find_elements(By.TAG_NAME, "form")
            cards = driver.find_elements(By.XPATH, "//*[contains(text(),'R$') or contains(text(),'Free') or contains(text(),'Pro')]")
            log(f"  → {slug}: forms={len(forms)}, plan-cards={len(cards)}")

        elif slug == "vulndb":
            rows = driver.find_elements(By.CSS_SELECTOR, "table tr, [class*='row']")
            log(f"  → VulnDB: {len(rows)} linhas/registros")

    except Exception as e:
        log(f"  ⚠ Interação: {e}")


def run_sidebar_interaction_test(driver):
    """Testa todos os links do Sidebar em sequência rápida."""
    log("\n" + "="*60)
    log("  TESTE DE NAVEGAÇÃO VIA SIDEBAR")
    nav_links = driver.find_elements(By.CSS_SELECTOR, "aside a[href]")
    hrefs = [l.get_attribute("href") for l in nav_links if l.get_attribute("href")]
    log(f"  Sidebar: {len(hrefs)} links encontrados")
    sidebar_result = {"total": len(hrefs), "ok": 0, "errors": []}
    for href in hrefs:
        try:
            driver.get(href)
            time.sleep(1.2)
            body = driver.find_element(By.TAG_NAME, "body").text
            if len(body.strip()) > 50:
                sidebar_result["ok"] += 1
            else:
                sidebar_result["errors"].append(f"Página vazia: {href}")
        except Exception as e:
            sidebar_result["errors"].append(f"{href}: {e}")
    log(f"  Sidebar OK: {sidebar_result['ok']}/{sidebar_result['total']}")
    if sidebar_result["errors"]:
        for e in sidebar_result["errors"]:
            log(f"  ✗ {e}")
    screenshot(driver, "sidebar_nav", "_final")
    return sidebar_result


def main():
    log(f"\n{'#'*60}")
    log(f"  PenteIA v4.0 — QA Visual Automatizado")
    log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"  Screenshots -> {OUT_DIR}")
    log(f"{'#'*60}\n")

    driver = make_driver()
    driver.set_page_load_timeout(30)
    logged_in = False

    try:
        for slug, path, needs_login, desc in PAGES:
            if needs_login and not logged_in:
                log("\n>>> Fazendo login...")
                logged_in = do_login(driver)
                if not logged_in:
                    log("AVISO: Login falhou — páginas protegidas serão testadas sem auth")

            result = test_page(driver, slug, path, needs_login, desc)
            results.append(result)

        # Teste de navegação sidebar (já logado)
        if logged_in:
            driver.get(f"{BASE}/dashboard")
            wait_page_stable(driver)
            sidebar_res = run_sidebar_interaction_test(driver)
        else:
            sidebar_res = {"note": "Sem login — sidebar não testado"}

    finally:
        driver.quit()

    # ── Relatório Final ─────────────────────────────────────────────────────
    log(f"\n{'#'*60}")
    log("  RELATÓRIO FINAL")
    log(f"{'#'*60}")

    ok_count   = sum(1 for r in results if r["status"] == "ok")
    warn_count = sum(1 for r in results if r["status"] == "warning")
    err_count  = sum(1 for r in results if r["status"] == "error")

    log(f"\n  Total: {len(results)} páginas | ✓ OK: {ok_count} | ⚠ Warning: {warn_count} | ✗ Erro: {err_count}\n")

    bugs = []
    for r in results:
        status_icon = "✓" if r["status"] == "ok" else "⚠" if r["status"] == "warning" else "✗"
        log(f"  {status_icon} [{r['load_time_ms']:4d}ms] {r['desc']:<35} {r['path']}")
        for issue in r["issues"]:
            log(f"       └─ {issue}")
            bugs.append({"page": r["desc"], "path": r["path"], "issue": issue})

    log(f"\n  Screenshots salvos em: {OUT_DIR}")

    # Salva JSON
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {"total": len(results), "ok": ok_count, "warnings": warn_count, "errors": err_count},
        "bugs": bugs,
        "pages": results,
        "sidebar": sidebar_res if 'sidebar_res' in dir() else {},
    }
    report_path = OUT_DIR / "qa_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    log(f"  Relatório JSON: {report_path}")

    return report


if __name__ == "__main__":
    report = main()
    # Exit code baseado em erros
    exit(1 if report["summary"]["errors"] > 0 else 0)
