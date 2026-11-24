#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT Portugal
Auditor de Segurança para Servidores e Ferramentas MCP
Auditor e verificador de segurança para servidores e manifestos MCP (Model Context Protocol). Aplicação web no navegador e CLI.

Standard: Normas Europeias de Cibersegurança em IA e Princípio do Menor Privilégio
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
METADATA_HOSTS = ["metadata.cloud-provider.internal", "metadata.internal", "instance-data.internal", "cloud-metadata.service"]

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
                "category": "Execução de Comandos",
                "title": "Execução Direta de Interpretador de Shell Detetada",
                "detail": "O servidor executa o interpretador '{cmd}' diretamente sem isolamento em contentor.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Remova a execução direta de shells. Utilize contentores Docker isolados com privilégios mínimos."
            })
            penalty += 35

        # 2. Dynamic command flags
        for arg in args:
            a_str = str(arg).lower()
            if a_str in ["-c", "/c", "-command"] or "invoke-expression" in a_str or "eval(" in a_str:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Execução de Comandos",
                    "title": "Argumentos com Parâmetros de Execução Arbitrária de Comandos",
                    "detail": "Foi detetado o parâmetro '{arg}', permitindo execução dinâmica de comandos.".replace("{arg}", str(arg)),
                    "remediation": "Elimine parâmetros como -c ou avaliações dinâmicas. Parametrize ferramentas de modo restrito."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acesso ao Sistema de Ficheiros",
                    "title": "Montagem de Diretório Raiz do Sistema de Ficheiros",
                    "detail": "O caminho '{path}' concede permissão total a todo o disco do sistema anfitrião.".replace("{path}", str(arg)),
                    "remediation": "Limite os caminhos permitidos a pastas de trabalho dedicadas e isoladas."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acesso ao Sistema de Ficheiros",
                    "title": "Acesso Permitido a Diretórios Sensíveis do Sistema",
                    "detail": "O servidor possui permissão para ler ficheiros em diretórios protegidos ('{path}').".replace("{path}", str(arg)),
                    "remediation": "Bloqueie o acesso a chaves SSH e diretórios confidenciais do sistema operativo."
                })
                penalty += 30

        # 4. Plaintext secrets
        for env_k, env_v in env.items():
            k_lower = env_k.lower()
            v_str = str(env_v or "")
            if any(s_k in k_lower for s_k in ["db_url", "database_url", "conn_str", "postgres", "mysql"]):
                if "password" in v_str.lower() or "://" in v_str:
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Credenciais Expostas",
                        "title": "Cadeia de Ligação de Base de Dados com Palavra-passe em Texto Limpo",
                        "detail": "A variável de ambiente '{key}' contém credenciais de acesso expostas.".replace("{key}", env_k),
                        "remediation": "Substitua por referência de variável de ambiente: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20
            elif any(s_k in k_lower for s_k in ["api_key", "secret", "token", "auth", "private_key"]):
                if not (v_str.startswith("${") and v_str.endswith("}")):
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Credenciais Expostas",
                        "title": "Chave de API ou Token Privado Exposto em Texto Limpo",
                        "detail": "A variável '{key}' contém um token privado codificado diretamente.".replace("{key}", env_k),
                        "remediation": "Utilize variáveis de ambiente do sistema anfitrião: ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20

        # 5. Supply chain unpinned packages
        if cmd in ["npx", "uvx", "pipx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for a in args:
                a_str = str(a)
                if not a_str.startswith("-"):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str[1:] or "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Cadeia de Fornecimento",
                    "title": "Pacote Remoto sem Fixação de Versão (Risco de Fornecimento)",
                    "detail": "O pacote '{pkg}' é obtido dinamicamente sem especificação de versão imutável.".replace("{pkg}", pkg_name),
                    "remediation": "Fixe a versão exata do pacote (exemplo: {pkg}@1.0.0 ou ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_HOSTS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Rede e Mitigação de SSRF",
                    "title": "Possibilidade de SSRF ou Ligação a Metadados de Nuvem",
                    "detail": "O argumento '{target}' aponta para serviços de metadados internos ou endpoints protegidos.".replace("{target}", a_str),
                    "remediation": "Configure listas de permissões estritas de domínios corporativos e bloqueie serviços de metadados internos."
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
            elif any(mh in a_str for mh in METADATA_HOSTS):
                cleaned_args.append("metadata-blocked.internal")
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
        description="Auditor de Segurança para Ficheiros de Configuração MCP (Model Context Protocol)."
    )
    parser.add_argument("-file", "--file", "-f", required=True, help="Caminho para o ficheiro mcp.json ou configuração do cliente de inteligência artificial")
    parser.add_argument("-strict", "--strict", action="store_true", help="Modo estrito: terminar com código de saída 1 se qualquer inconformidade for detetada")
    parser.add_argument("-harden", "--harden", "-o", help="Exportar ficheiro JSON com configuração corrigida e blindada")
    parser.add_argument("-json", "--json", action="store_true", help="Apresentar saída em formato JSON estruturado")

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
        print(f"Configuração blindada gravada com sucesso em: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"AUDITORIA DE SEGURANÇA MCP: TAVARDT Portugal")
        print(f"Standard: Normas Europeias de Cibersegurança em IA e Princípio do Menor Privilégio")
        print(f"Servidores Analisados: {report['server_count']}")
        print(f"Índice de Segurança: {report['score']} / 100")
        print(f"Vulnerabilidades Detetadas: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Nenhuma vulnerabilidade detetada. Configuração em conformidade com o princípio de menor privilégio.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
