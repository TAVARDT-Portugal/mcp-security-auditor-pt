# Auditor de Seguranca para Servidores e Ferramentas MCP

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![Standard](https://img.shields.io/badge/Standard-EU%20Cybersecurity-3b82f6?style=for-the-badge)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981?style=for-the-badge)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Auditor e verificador de seguranca para servidores e manifestos MCP (Model Context Protocol). Aplicacao web no navegador e CLI.

Desenvolvido para organizacoes e equipas tecnicas em **Portugal**, este repositorio disponibiliza uma solucao completa para a auditoria de configuracoes e manifestos do **Model Context Protocol (MCP)**, prevenindo incidentes de seguranca em agentes autonomos de Inteligencia Artificial.

---

## Modos de Operacao

### 1. Aplicacao Web no Navegador (GitHub Pages)
Utilize a aplicacao interativa diretamente a partir do navegador:
- **Ligacao Oficial**: [https://tavardt-portugal.github.io/mcp-security-auditor-pt/](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
- **Privacidade Absoluta**: Processamento 100% estatico no motor JavaScript do navegador. Nenhuma informacao ou credencial e enviada para servidores remotos.

### 2. Utilitario de Linha de Comandos (CLI)
Para integracao em fluxos de validacao continua (CI/CD) ou utilizacao local no terminal:

```bash
# Execucao basica sobre o ficheiro de configuracao
python mcp_security_scanner.py --file mcp.json

# Modo rigoroso para controlo de qualidade (retorna codigo 1 perante qualquer vulnerabilidade)
python mcp_security_scanner.py --file mcp.json --strict

# Geracao automatica de configuracao corrigida e blindada (Hardened)
python mcp_security_scanner.py --file mcp.json --harden mcp-hardened.json

# Exportacao do relatorio estruturado em JSON
python mcp_security_scanner.py --file mcp.json --json
```

---

## Vetores de Seguranca Auditados

1. **Permissoes de Sistema de Ficheiros**: Verificacao de acessos indevidos a pastas raiz (`/`, `C:\`) ou diretorios protegidos (`/etc`, `~/.ssh`).
2. **Execucao Arbitraria de Comandos**: Bloqueio de interpretadores de terminal sem isolamento (`bash`, `sh`, `powershell`, `cmd`) e remocao de parametros de execucao dinamica.
3. **Protecao de Credenciais**: Inspecao de segredos expostos (chaves de API, palavras-passe e ligacoes de bases de dados).
4. **Seguranca da Cadeia de Fornecimento**: Confirmacao de imutabilidade e fixacao estrita de versoes em pacotes distribuidos via `npx` ou `uvx`.
5. **Mitigacao de SSRF**: Deteccao de tentativas de conexao a interfaces internas e enderecos de metadados de cloud (`169.254.169.254`).

---

## Integracao em GitHub Actions

```yaml
name: MCP Security Gate
on: [push, pull_request]

jobs:
  audit-mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Executar Auditoria MCP
        run: |
          python mcp_security_scanner.py --file config/mcp.json --strict
```

---

## Conformidade e Referencial Tecnico

- **Jurisdicao**: Portugal
- **Quadro Normativo**: Normas Europeias de Ciberseguranca em IA e Principio do Menor Privilegio
- **Organizacao Mantenedora**: [TAVARDT-Portugal](https://github.com/TAVARDT-Portugal)

## Portais Institucionais TAVARDT

- **Portal Principal**: [https://ag.tavardt.com/pt/](https://ag.tavardt.com/pt/)
- **Ferramentas de Ciberseguranca**: [https://tools.tavardt.com/pt/](https://tools.tavardt.com/pt/)
- **Contacto Tecnico**: [https://ag.tavardt.com/pt/contato/](https://ag.tavardt.com/pt/contato/)

---

### Licenca
Distribuido ao abrigo da licenca MIT. Consulte o ficheiro [LICENSE](LICENSE) para mais detalhes.
