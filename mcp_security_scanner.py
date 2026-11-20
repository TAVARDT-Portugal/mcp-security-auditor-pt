#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT Portugal
Auditor de Seguranca para Servidores e Ferramentas MCP
Auditor e verificador de seguranca para servidores e manifestos MCP (Model Context Protocol). Aplicacao web no navegador e CLI.

Standard: Normas Europeias de Ciberseguranca em IA e Principio do Menor Privilegio
Repository: https://github.com/TAVARDT-Portugal/mcp-security-auditor-pt
Online Web App: https://tavardt-portugal.github.io/mcp-security-auditor-pt/
"""

import os
import sys
import json
import re
import argparse

DANGEROUS_SHELLS = ["bash", "sh", "zsh", "powershell", "powershell.exe", "cmd", "cmd.exe"]
ROOT_PATHS = ["/", "\\", "c:\\", "c:/", "d:\\", "d:/", "~", "$home", "%userprofile%"]
SENSITIVE_PATHS = ["/etc", "/var", "/root", ".ssh", ".aws", ".gnupg", "system32", "appdata"]
METADATA_IPS = ["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1"]

def analyze_mcp_config(config_data):
    servers = {}
    if "mcpServers" in config_data and isinstance(config_data["mcpServers"], dict):
        servers = config_data["mcpServers"]
    elif isinstance(config_data, dict):
        servers = config_data

    findings = []
    penalty = 0

    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue

        cmd = (srv.get("command") or "").strip().lower()
        args = srv.get("args") or []
        env = srv.get("env") or {}

        # 1. Shell execution
        if cmd in DANGEROUS_SHELLS:
            findings.append({
                "server": s_name,
                "severity": "CRITICAL",
                "category": "Execucao de Comandos",
                "title": "Execucao Direta de Interpretador de Shell Detetada",
                "detail": "O servidor executa o interpretador '{cmd}' diretamente sem isolamento.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Remova a execucao direta de shells. Utilize contentores Docker isolados."
            })
            penalty += 35

        # 2. Dynamic command flags
        for arg in args:
            a_str = str(arg).lower()
            if a_str in ["-c", "/c", "-command"] or "invoke-expression" in a_str or "eval(" in a_str:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Execucao de Comandos",
                    "title": "Argumentos com Flags de Execucao Arbitraria de Comandos",
                    "detail": "Foi detetado o parametro '{arg}', permitindo instrucoes dinamicas.".replace("{arg}", str(arg)),
                    "remediation": "Elimine flags como -c ou eval. Parametrize ferramentas de modo estrito."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acesso a Ficheiros",
                    "title": "Montagem de Diretorio Raiz do Sistema de Ficheiros",
                    "detail": "O caminho '{path}' concede permissao total a todo o disco do hospedeiro.".replace("{path}", str(arg)),
                    "remediation": "Limite os caminhos permitidos a pastas de trabalho especificas."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acesso a Ficheiros",
                    "title": "Acesso Permitido a Diretorios Sensiveis do Sistema",
                    "detail": "O servidor tem permissao para aceder a ficheiros em '{path}'.".replace("{path}", str(arg)),
                    "remediation": "Bloqueie o acesso a chaves SSH e pastas protegidas do sistema operativo."
                })
                penalty += 30

        # 4. Exposed secrets in env
        for e_key, e_val in env.items():
            val = str(e_val or "").strip()
            if val.startswith("${") and val.endswith("}"):
                continue

            is_secret_key = bool(re.search(r"token|secret|key|password|passwd|auth|bearer", e_key, re.I))
            is_sensitive_url = bool(re.search(r"postgres:|mongodb:|mysql:|redis:", val, re.I) and "@" in val)
            is_known_prefix = bool(re.match(r"^sk-[a-zA-Z0-9_-]{20,}|^ghp_[a-zA-Z0-9]{20,}|^xoxb-[a-zA-Z0-9-]{20,}|^AKIA[0-9A-Z]{16}", val))

            if is_sensitive_url:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Credenciais Expostas",
                    "title": "Cadeia de Ligacao de Base de Dados com Palavra-passe Exposta",
                    "detail": "A variavel de ambiente '{key}' contem credenciais de ligacao expostas.".replace("{key}", e_key),
                    "remediation": "Substitua por referencia de variavel de ambiente: ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 30
            elif is_known_prefix or (is_secret_key and len(val) >= 10):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Credenciais Expostas",
                    "title": "Chave de API ou Token Privado Exposto em Texto Simples",
                    "detail": "A variavel '{key}' contem um token secreto codificado diretamente.".replace("{key}", e_key),
                    "remediation": "Utilize variaveis de ambiente do sistema hospedeiro: ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 25

        # 5. Supply chain / unpinned packages
        if cmd in ["npx", "uvx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for arg in args:
                a_str = str(arg)
                if a_str == "-y" or a_str.startswith("--"):
                    continue
                if not pkg_found and ("/" in a_str or "-" in a_str or len(a_str) > 2):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str and a_str.rfind("@") > 0:
                        is_pinned = True
                    if "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Cadeia de Fornecimento",
                    "title": "Pacote Remoto sem Fixacao de Versao (Risco de Supply Chain)",
                    "detail": "O pacote '{pkg}' e transferido dinamicamente sem indicacao de versao imutavel.".replace("{pkg}", pkg_name),
                    "remediation": "Fixe a versao exata do pacote (ex: {pkg}@1.0.0 ou ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_IPS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Rede e SSRF",
                    "title": "Possibilidade de SSRF ou Ligacao a Metadados de Cloud",
                    "detail": "O argumento '{target}' aponta para servicos locais ou metadados de nuvem.".replace("{target}", a_str),
                    "remediation": "Configure listas de permissoes estritas de dominios e bloqueie IPs de metadados."
                })
                penalty += 20

    score = max(0, 100 - penalty)
    return {
        "server_count": len(servers),
        "score": score,
        "findings": findings,
        "servers": servers
    }

def harden_config(servers):
    hardened = {"mcpServers": {}}
    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue
        h_cmd = srv.get("command", "")
        h_args = list(srv.get("args") or [])

        # Wrap shells
        if h_cmd.lower() in DANGEROUS_SHELLS:
            h_cmd = "docker"
            h_args = ["run", "--rm", "-i", "--read-only", "--cap-drop=ALL", "sandbox-runner:latest"]

        # Restrict root or critical paths
        cleaned_args = []
        for a in h_args:
            a_str = str(a).strip().lower()
            if a_str in ROOT_PATHS:
                cleaned_args.append("/workspace/sandbox/app-data")
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                cleaned_args.append("/workspace/sandbox/isolated-storage")
            elif "169.254.169.254" in a_str:
                cleaned_args.append("127.0.0.1:blocked")
            elif h_cmd in ["npx", "uvx"] and a_str.startswith("@modelcontextprotocol/server-") and "@" not in a_str[1:]:
                cleaned_args.append(str(a) + "@0.6.2")
            else:
                cleaned_args.append(a)

        h_srv = {
            "command": h_cmd,
            "args": cleaned_args
        }

        # Abstract secrets into env vars
        if "env" in srv and isinstance(srv["env"], dict):
            h_env = {}
            for e_k, e_v in srv["env"].items():
                v_str = str(e_v or "")
                if v_str.startswith("${") and v_str.endswith("}"):
                    h_env[e_k] = v_str
                else:
                    h_env[e_k] = "${" + e_k.upper() + "}"
            h_srv["env"] = h_env

        hardened["mcpServers"][s_name] = h_srv
    return hardened

def main():
    parser = argparse.ArgumentParser(
        description="Auditor de Seguranca para Ficheiros de Configuracao MCP (Model Context Protocol)."
    )
    parser.add_argument("--file", "-f", required=True, help="Caminho para o ficheiro mcp.json ou claude_desktop_config.json")
    parser.add_argument("--strict", action="store_true", help="Modo estrito: terminar com codigo 1 perante qualquer vulnerabilidade")
    parser.add_argument("--harden", "-o", help="Exportar ficheiro JSON com configuracao corrigida e blindada")
    parser.add_argument("--json", action="store_true", help="Apresentar resultado em formato JSON estruturado")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"Error reading JSON from {args.file}: {e}", file=sys.stderr)
        sys.exit(2)

    report = analyze_mcp_config(cfg)

    if args.harden:
        hardened_json = harden_config(report["servers"])
        with open(args.harden, "w", encoding="utf-8") as out_f:
            json.dump(hardened_json, out_f, indent=2)
        print(f"Configuracao blindada guardada com sucesso em: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"AUDITORIA DE SEGURANCA MCP: TAVARDT Portugal")
        print(f"Standard: Normas Europeias de Ciberseguranca em IA e Principio do Menor Privilegio")
        print(f"Servidores Analisados: {report['server_count']}")
        print(f"Indice de Seguranca: {report['score']} / 100")
        print(f"Vulnerabilidades Detetadas: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Nenhuma vulnerabilidade detetada. Configuracao em conformidade com o principio do menor privilegio.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    # Exit code determination
    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
