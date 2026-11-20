# Auditor de Segurança para Servidores e Ferramentas MCP

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![Standard](https://img.shields.io/badge/Standard-EU%20Cybersecurity-3b82f6?style=for-the-badge)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981?style=for-the-badge)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Auditor e verificador de segurança para servidores e manifestos MCP (Model Context Protocol). Aplicação web no navegador e CLI.

Desenvolvido para organizações e equipas técnicas em **Portugal**, este repositório disponibiliza uma solução completa para a auditoria de configurações e manifestos do **Model Context Protocol (MCP)**, prevenindo incidentes de segurança em agentes autónomos de Inteligência Artificial.

---

## Modos de Operação

### 1. Aplicação Web no Navegador (GitHub Pages)
Utilize a aplicação interativa diretamente a partir do navegador:
- **Ligação Oficial**: [https://tavardt-portugal.github.io/mcp-security-auditor-pt/](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
- **Privacidade Absoluta**: Processamento 100% estático no motor JavaScript do navegador. Nenhuma informação ou credencial é enviada para servidores remotos.

### 2. Utilitário de Linha de Comandos (CLI)
Para integração em fluxos de validação contínua (CI/CD) ou utilização local no terminal:

```bash
# Execução básica sobre o ficheiro de configuração
python mcp_security_scanner.py --file mcp.json

# Modo rigoroso para controlo de qualidade (retorna código 1 perante qualquer vulnerabilidade)
python mcp_security_scanner.py --file mcp.json --strict

# Geração automática de configuração corrigida e blindada (Hardened)
python mcp_security_scanner.py --file mcp.json --harden mcp-hardened.json

# Exportação do relatório estruturado em JSON
python mcp_security_scanner.py --file mcp.json --json
```

---

## Vetores de Segurança Auditados

1. **Permissões de Sistema de Ficheiros**: Verificação de acessos indevidos a pastas raiz (`/`, `C:\`) ou diretórios protegidos (`/etc`, `~/.ssh`).
2. **Execução Arbitrária de Comandos**: Bloqueio de interpretadores de terminal sem isolamento (`bash`, `sh`, `powershell`, `cmd`) e remoção de parâmetros de execução dinâmica.
3. **Proteção de Credenciais**: Inspeção de segredos expostos (chaves de API, palavras-passe e ligações de bases de dados).
4. **Segurança da Cadeia de Fornecimento**: Confirmação de imutabilidade e fixação estrita de versões em pacotes distribuídos via `npx` ou `uvx`.
5. **Mitigação de SSRF**: Deteção de tentativas de ligação a interfaces locais e serviços internos protegidos.

---

## Integração em GitHub Actions

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

## Conformidade e Referencial Técnico

- **Jurisdição**: Portugal
- **Quadro Normativo**: Normas Europeias de Cibersegurança em IA e Princípio do Menor Privilégio
- **Organização Mantenedora**: [TAVARDT-Portugal](https://github.com/TAVARDT-Portugal)

## Portais Institucionais TAVARDT

- **Portal Principal**: [https://ag.tavardt.com/pt/](https://ag.tavardt.com/pt/)
- **Central de Ferramentas**: [https://tools.tavardt.com/pt/](https://tools.tavardt.com/pt/)
- **Contacto Técnico**: [https://ag.tavardt.com/pt/contato/](https://ag.tavardt.com/pt/contato/)

---

### Licença
Distribuído ao abrigo da licença MIT. Consulte o ficheiro [LICENSE](LICENSE) para mais detalhes.
