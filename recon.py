#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PenteIA - Módulo de Reconhecimento (recon)

Dois recursos, usáveis juntos ou separadamente:
  1) Resolução de domínio/URL -> IP(s) do host (DNS, IPv4 e IPv6)
  2) Varredura de portas TCP do host, na FAIXA escolhida pelo usuário (connect scan)

O resultado alimenta o scanner de vulnerabilidades: portas web abertas viram
alvos sugeridos para o scanner.py.

###############################################################################
#                               AVISO ÉTICO                                   #
###############################################################################
# Use SOMENTE em hosts que você tem PERMISSÃO EXPLÍCITA para testar.          #
# Varredura de portas sem autorização pode ser ilegal em muitas jurisdições.  #
# Esta ferramenta faz um "connect scan" simples (sem evasão/stealth) e é      #
# destinada a testes de segurança autorizados, CTFs e laboratórios.          #
###############################################################################
"""

import os
import sys
import json
import time
import socket
import argparse
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from colorama import init, Fore, Style
from tqdm import tqdm

# Inicializa colorama
init(autoreset=True)

# Garante saída UTF-8 no terminal (evita erros no console do Windows / cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# Mapa de portas comuns -> serviço (para enriquecer o relatório)
SERVICOS_COMUNS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    587: "smtp-sub", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    2376: "docker-tls", 3000: "http-dev", 3306: "mysql", 3389: "rdp",
    4444: "metasploit", 5000: "http-alt", 5432: "postgresql", 5601: "kibana",
    5900: "vnc", 5985: "winrm", 6379: "redis", 7001: "weblogic", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
}

# Portas web -> sugeridas para o scanner de vulnerabilidades
PORTAS_WEB = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090}

# Portas que tipicamente falam TLS (banner via handshake) e HTTP (banner via GET)
PORTAS_TLS = {443, 465, 636, 993, 995, 8443, 9443}
PORTAS_HTTP = {80, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090}

# Conjunto "top" de portas comuns (varredura rápida padrão)
TOP_PORTS = sorted(SERVICOS_COMUNS.keys())


# ---------------------------------------------------------------------------
# 1) Resolução de domínio -> IP
# ---------------------------------------------------------------------------
def extrair_host(alvo):
    """Aceita domínio, URL (http://...) ou IP e devolve apenas o hostname/IP."""
    alvo = alvo.strip()
    if "://" in alvo:
        netloc = urlparse(alvo).netloc
    else:
        # pode vir "host:porta" ou "host/caminho"
        netloc = alvo.split("/")[0]
    # remove credenciais e porta
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    if netloc.startswith("["):  # IPv6 literal [::1]:porta
        return netloc[1:].split("]")[0]
    if ":" in netloc:
        netloc = netloc.split(":", 1)[0]
    return netloc


def eh_ip(valor):
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def classificar_ip(ip):
    """Devolve uma observação sobre o IP (privado, loopback, etc.)."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if obj.is_loopback:
        return "loopback"
    if obj.is_private:
        return "privado (rede interna)"
    if obj.is_reserved or obj.is_link_local:
        return "reservado/link-local"
    return "público"


def resolver_dominio(alvo):
    """Resolve um domínio/URL para seus IPs (IPv4 e IPv6). Retorna um dict."""
    host = extrair_host(alvo)
    resultado = {"alvo": alvo, "host": host, "is_ip": eh_ip(host), "ips": [], "erro": None}

    if resultado["is_ip"]:
        resultado["ips"] = [host]
        return resultado

    try:
        infos = socket.getaddrinfo(host, None)
        ips = []
        for familia, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        resultado["ips"] = ips
        # Nome canônico (best-effort)
        try:
            resultado["canonico"] = socket.getfqdn(host)
        except Exception:
            pass
    except socket.gaierror as e:
        resultado["erro"] = f"Falha ao resolver '{host}': {e}"
    except Exception as e:
        resultado["erro"] = f"Erro inesperado ao resolver '{host}': {e}"

    return resultado


def imprimir_resolucao(res):
    print(f"\n{Fore.BLUE}[*] Resolvendo: {Fore.WHITE}{res['host']}")
    if res["erro"]:
        print(f"{Fore.RED}[!] {res['erro']}")
        return
    if res["is_ip"]:
        print(f"{Fore.GREEN}[+] Já é um IP: {res['host']} ({classificar_ip(res['host'])})")
        return
    if not res["ips"]:
        print(f"{Fore.YELLOW}[!] Nenhum IP encontrado.")
        return
    print(f"{Fore.GREEN}[+] {len(res['ips'])} IP(s) encontrado(s):")
    for ip in res["ips"]:
        print(f"      {Fore.WHITE}{ip}  {Style.DIM}({classificar_ip(ip)})")
    # Dica de CDN só faz sentido com múltiplos IPs públicos
    publicos = [ip for ip in res["ips"] if classificar_ip(ip) == "público"]
    if len(publicos) > 1:
        print(f"{Fore.YELLOW}[i] Múltiplos IPs públicos podem indicar CDN/load balancer "
              f"(você estaria varrendo o CDN, não o servidor de origem).")


# ---------------------------------------------------------------------------
# 2) Varredura de portas (connect scan)
# ---------------------------------------------------------------------------
def parse_portas(spec):
    """Converte '1-1024', '80,443', '1-100,8080', 'top' ou 'all' em lista de portas."""
    spec = spec.strip().lower()
    if spec in ("top", "comuns"):
        return list(TOP_PORTS)
    if spec in ("all", "todas", "1-65535"):
        return list(range(1, 65536))

    portas = set()
    for parte in spec.split(","):
        parte = parte.strip()
        if not parte:
            continue
        if "-" in parte:
            ini, fim = parte.split("-", 1)
            ini, fim = int(ini), int(fim)
            if ini > fim:
                ini, fim = fim, ini
            for p in range(ini, fim + 1):
                portas.add(p)
        else:
            portas.add(int(parte))

    # Valida o intervalo
    portas = {p for p in portas if 1 <= p <= 65535}
    if not portas:
        raise ValueError("Nenhuma porta válida na faixa informada.")
    return sorted(portas)


def calibrar_timeout(ip, base_timeout, verbose=True):
    """Mede o RTT até o host (conexão aceita ou recusada em portas de prova) e
    devolve um timeout adaptativo. As provas rodam em paralelo (rápido)."""
    portas_prova = [443, 80, 22, 3389, 8080]

    def medir(p):
        t0 = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                try:
                    s.connect((ip, p))
                    return time.perf_counter() - t0             # aceita = RTT
                except ConnectionRefusedError:
                    return time.perf_counter() - t0             # RST = RTT também
                except (socket.timeout, OSError):
                    return None                                 # filtrada: não informa RTT
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(portas_prova)) as ex:
        rtts = [r for r in ex.map(medir, portas_prova) if r is not None]

    if rtts:
        rtt = min(rtts)
        adaptativo = min(max(rtt * 5, base_timeout, 0.5), 5.0)
        if verbose:
            print(f"{Fore.BLUE}[*] RTT ~{rtt*1000:.0f} ms  ->  timeout adaptativo {adaptativo:.2f}s")
        return adaptativo, rtt
    if verbose:
        print(f"{Fore.YELLOW}[i] Sem RTT mensurável (portas de prova não responderam); "
              f"usando timeout {base_timeout:.2f}s")
    return base_timeout, None


def checar_porta(ip, porta, timeout):
    """Connect scan de uma porta. Retorna 'open', 'closed' (RST) ou 'filtered' (timeout)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((ip, porta))
                return "open"
            except socket.timeout:
                return "filtered"
            except ConnectionRefusedError:
                return "closed"
            except OSError:
                return "filtered"
    except Exception:
        return "filtered"


def _passada(ip, portas, timeout, workers, desc):
    """Uma passada de varredura. Retorna {porta: estado}."""
    estados = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futuros = {executor.submit(checar_porta, ip, p, timeout): p for p in portas}
        for futuro in tqdm(as_completed(futuros), total=len(futuros), desc=desc, ncols=80, leave=False):
            estados[futuros[futuro]] = futuro.result()
    return estados


def _eh_texto(dados):
    """Heurística: a maioria dos bytes é imprimível?"""
    if not dados:
        return False
    printaveis = sum(1 for b in dados if b in (9, 10, 13) or 32 <= b <= 126)
    return printaveis / len(dados) > 0.85


def _formatar_banner(dados):
    """Texto limpo (primeira linha) ou hex para conteúdo binário."""
    if not dados:
        return ""
    if _eh_texto(dados):
        txt = dados.decode("utf-8", errors="replace").strip()
        return txt.splitlines()[0][:120] if txt else ""
    return "hex:" + dados[:24].hex()


def grab_banner(ip, porta, host, timeout):
    """Captura banner com o probe adequado ao serviço: TLS (handshake), HTTP (GET) ou passivo."""
    timeout = max(timeout, 2.0)

    # Serviços TLS: faz o handshake e devolve versão + CN do certificado
    if porta in PORTAS_TLS:
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sni = host if (host and not eh_ip(host)) else None
            with socket.create_connection((ip, porta), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as ts:
                    versao = ts.version() or "TLS"
                    cn = ""
                    cert = ts.getpeercert()
                    if cert:
                        for campo in cert.get("subject", ()):
                            for chave, valor in campo:
                                if chave == "commonName":
                                    cn = valor
                    return f"{versao}" + (f" | CN={cn}" if cn else "")
        except Exception:
            return ""

    # HTTP e demais serviços
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            s.settimeout(timeout)
            if porta in PORTAS_HTTP:
                req = (f"GET / HTTP/1.0\r\nHost: {host or ip}\r\n"
                       f"User-Agent: PenteIA-Recon\r\n\r\n")
                s.sendall(req.encode())
            dados = s.recv(512)
            # Para HTTP, junta a linha de status com o cabeçalho 'Server:' (se houver)
            if porta in PORTAS_HTTP and dados:
                linhas = dados.decode("utf-8", errors="replace").splitlines()
                status = linhas[0].strip() if linhas else ""
                server = next((l.strip() for l in linhas if l.lower().startswith("server:")), "")
                return (status + (f" | {server}" if server else ""))[:120]
            return _formatar_banner(dados)
    except Exception:
        return ""


def scan_portas(ip, portas, host=None, timeout=1.0, workers=100, banner=False,
                retry=True, retry_timeout=None):
    """Varre as portas (com passe de reteste opcional) e devolve a lista de abertas."""
    workers = max(1, min(workers, 500))  # teto de segurança

    print(f"\n{Fore.BLUE}[*] Varrendo {len(portas)} porta(s) em {Fore.WHITE}{ip}{Fore.BLUE} "
          f"(timeout={timeout:.2f}s, workers={workers})...")
    estados = _passada(ip, portas, timeout, workers, "Portas")

    # Passe de reteste: só as portas que deram timeout (filtradas), com timeout maior
    # e CONCORRÊNCIA BAIXA (segundo olhar cuidadoso — evita perda por rajada de SYN).
    filtradas = [p for p, st in estados.items() if st == "filtered"]
    # Se quase tudo está filtrado, o host dropa pacotes (firewall): retestar milhares
    # é lento e pouco útil. Avisa e pula o reteste automático nesse caso.
    drop_all = len(portas) > 50 and len(filtradas) > 0.9 * len(portas)
    if retry and filtradas and drop_all and len(filtradas) > 500:
        print(f"{Fore.YELLOW}[i] {len(filtradas)}/{len(portas)} portas filtradas — o host parece "
              f"dropar pacotes (firewall). Reteste automático pulado (use faixas menores para precisão).")
    elif retry and filtradas:
        rt = retry_timeout or min(max(timeout * 3, 3.0), 8.0)
        retry_workers = min(workers, 20)
        print(f"{Fore.BLUE}[*] Reteste de {len(filtradas)} porta(s) sem resposta "
              f"(timeout={rt:.2f}s, workers={retry_workers})...")
        for p, st in _passada(ip, filtradas, rt, retry_workers, "Reteste").items():
            estados[p] = st

    abertas_portas = sorted(p for p, st in estados.items() if st == "open")

    if abertas_portas and banner:
        print(f"{Fore.BLUE}[*] Capturando banners de {len(abertas_portas)} porta(s) aberta(s)...")

    abertas = []
    for p in abertas_portas:
        b = grab_banner(ip, p, host, timeout) if banner else ""
        abertas.append({
            "porta": p,
            "estado": "aberta",
            "servico": SERVICOS_COMUNS.get(p, "desconhecido"),
            "banner": b,
        })
    return abertas


def imprimir_portas(ip, abertas):
    if not abertas:
        print(f"{Fore.YELLOW}[!] Nenhuma porta aberta encontrada em {ip} na faixa testada.")
        return
    print(f"\n{Fore.GREEN}[+] {len(abertas)} porta(s) aberta(s) em {Fore.WHITE}{ip}{Fore.GREEN}:")
    print(f"    {'PORTA':<8}{'SERVIÇO':<16}BANNER")
    print(f"    {'-'*8}{'-'*16}{'-'*30}")
    for p in abertas:
        cor = Fore.MAGENTA if p["porta"] in PORTAS_WEB else Fore.WHITE
        print(f"    {cor}{p['porta']:<8}{Fore.WHITE}{p['servico']:<16}{Style.DIM}{p['banner']}")


def sugerir_scanner(ip, abertas):
    """Sugere comandos do scanner de vulnerabilidades para as portas web abertas."""
    web = [p for p in abertas if p["porta"] in PORTAS_WEB]
    if not web:
        return
    print(f"\n{Fore.CYAN}[>] Portas web detectadas — você pode escanear vulnerabilidades com:")
    for p in web:
        esquema = "https" if p["porta"] in (443, 8443) else "http"
        sufixo = "" if p["porta"] in (80, 443) else f":{p['porta']}"
        print(f"      {Fore.WHITE}python scanner.py --url {esquema}://{ip}{sufixo}/")


# ---------------------------------------------------------------------------
# Relatório
# ---------------------------------------------------------------------------
def salvar_relatorio(alvo, resolucao, resultados_por_ip):
    os.makedirs("relatorios", exist_ok=True)
    host_slug = (resolucao.get("host") or "alvo").replace(".", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    caminho = os.path.join("relatorios", f"recon_{host_slug}_{timestamp}.json")

    relatorio = {
        "alvo": alvo,
        "timestamp": datetime.now().isoformat(),
        "host": resolucao.get("host"),
        "ips": resolucao.get("ips", []),
        "resultados": resultados_por_ip,  # {ip: [portas...]}
    }
    try:
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(relatorio, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.GREEN}[+] Relatório salvo em: {caminho}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Não foi possível salvar o relatório: {e}")


# ---------------------------------------------------------------------------
# Banner + CLI
# ---------------------------------------------------------------------------
def banner():
    print(f"""{Fore.CYAN}
  ╔══════════════════════════════════════════════════════════╗
  ║ {Fore.GREEN}PenteIA - Recon{Fore.CYAN}                                          ║
  ║ {Fore.YELLOW}Resolução de domínio + varredura de portas (connect){Fore.CYAN}     ║
  ╚══════════════════════════════════════════════════════════╝
{Fore.RED}  ⚠  Use APENAS em hosts autorizados.""")


def main():
    parser = argparse.ArgumentParser(
        description="PenteIA Recon - resolve domínio para IP e varre portas TCP",
        epilog="Exemplos:\n"
               "  python recon.py exemplo.com --resolve-only\n"
               "  python recon.py exemplo.com --ports 1-1024\n"
               "  python recon.py 127.0.0.1 --ports 22,80,443,3000 --banner\n"
               "  python recon.py http://alvo.com --ports top -y",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("alvo", help="Domínio, URL ou IP do host")
    parser.add_argument("--ports", "-p", default="top",
                        help="Faixa de portas: 'top' (padrão), 'all', '1-1024', '80,443,8080'...")
    parser.add_argument("--timeout", "-t", type=float, default=1.0,
                        help="Timeout-base por porta em segundos (default: 1.0; piso do adaptativo)")
    parser.add_argument("--workers", "-w", type=int, default=50,
                        help="Conexões simultâneas (default: 50, máx: 500). "
                             "Valores altos perdem pacotes por rajada e reduzem a precisão.")
    parser.add_argument("--banner", "-b", action="store_true",
                        help="Captura banner dos serviços abertos (HTTP/TLS/passivo)")
    parser.add_argument("--no-adaptive", action="store_true",
                        help="Desativa o timeout adaptativo (usa --timeout fixo)")
    parser.add_argument("--no-retry", action="store_true",
                        help="Desativa o passe de reteste das portas filtradas")
    parser.add_argument("--resolve-only", action="store_true",
                        help="Apenas resolve o domínio para IP (não varre portas)")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Não pedir confirmação (modo automático)")
    parser.add_argument("--output", "-o", help="Caminho do relatório JSON (default: relatorios/)")
    args = parser.parse_args()

    banner()

    # 1) Resolução
    resolucao = resolver_dominio(args.alvo)
    imprimir_resolucao(resolucao)

    if resolucao["erro"] or not resolucao["ips"]:
        sys.exit(1)

    if args.resolve_only:
        return

    # Faixa de portas
    try:
        portas = parse_portas(args.ports)
    except ValueError as e:
        print(f"{Fore.RED}[!] Faixa de portas inválida: {e}")
        sys.exit(1)

    # Aviso para varreduras grandes
    if len(portas) > 5000:
        print(f"{Fore.YELLOW}[i] Você pediu {len(portas)} portas — pode demorar. "
              f"Considere aumentar --workers ou reduzir --timeout.")

    # Confirmação de autorização
    publicos = [ip for ip in resolucao["ips"] if classificar_ip(ip) == "público"]
    if publicos and not args.yes:
        print(f"\n{Fore.RED}ATENÇÃO: você vai varrer portas de IP(s) PÚBLICO(s): {', '.join(publicos)}")
        print(f"{Fore.RED}Faça isso APENAS com autorização explícita do dono do host.")
    if not args.yes:
        try:
            if input(f"\n{Fore.YELLOW}Deseja continuar a varredura? (S/N): ").strip().upper() != "S":
                print(f"{Fore.BLUE}Operação cancelada.")
                return
        except EOFError:
            print(f"{Fore.YELLOW}[!] Sem terminal interativo. Use -y para confirmar automaticamente.")
            return

    # 2) Varredura (para cada IP resolvido)
    resultados_por_ip = {}
    inicio = time.time()
    for ip in resolucao["ips"]:
        # Por simplicidade, o connect scan aqui cobre IPv4; IPv6 é resolvido mas
        # a varredura usa AF_INET. Avisamos se for IPv6.
        if ":" in ip:
            print(f"\n{Fore.YELLOW}[i] {ip} é IPv6 — varredura IPv6 não implementada nesta versão, pulando.")
            continue

        # Timeout adaptativo: calibra pelo RTT do host (salvo se desativado)
        if args.no_adaptive:
            timeout_ip = args.timeout
        else:
            timeout_ip, _ = calibrar_timeout(ip, args.timeout)

        abertas = scan_portas(ip, portas, host=resolucao["host"], timeout=timeout_ip,
                              workers=args.workers, banner=args.banner,
                              retry=not args.no_retry)
        imprimir_portas(ip, abertas)
        sugerir_scanner(ip, abertas)
        resultados_por_ip[ip] = abertas

    duracao = time.time() - inicio
    total_abertas = sum(len(v) for v in resultados_por_ip.values())
    print(f"\n{Fore.BLUE}═══════════════════ RESUMO ═══════════════════")
    print(f"{Fore.GREEN}[+] Host: {resolucao['host']} | IPs: {', '.join(resolucao['ips'])}")
    print(f"{Fore.GREEN}[+] Portas testadas: {len(portas)} | Abertas: {total_abertas}")
    print(f"{Fore.GREEN}[+] Tempo: {duracao:.1f}s")

    salvar_relatorio(args.alvo, resolucao, resultados_por_ip)
    print(f"\n{Fore.YELLOW}Use os resultados com responsabilidade e apenas para fins autorizados.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Varredura interrompida pelo usuário.")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Erro inesperado: {e}")
        import traceback
        traceback.print_exc()
