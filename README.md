# Auditor de Segurança para Model Context Protocol (MCP)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![MCP Spec](https://img.shields.io/badge/MCP-Protocol%20Spec-blue.svg)](https://modelcontextprotocol.io/)
[![Zero Trust](https://img.shields.io/badge/Architecture-Zero%20Trust-green.svg)](https://ag.tavardt.com/pt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Inspeção de Servidores e Clientes MCP, Validação de Permissões de Ferramentas e Isolamento de Recursos Críticos**

Desenvolvido e mantido pela divisão de cibersegurança e arquitetura de agentes autónomos da TAVARDT Portugal.

***

## Portais e Demonstração Online

Aceda à ferramenta interativa oficial e aos canais soberanos da TAVARDT:

* **Aplicação Web Oficial no GitHub Pages**: [https://tavardt-portugal.github.io/mcp-security-auditor-pt/](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
* **Portal Institucional**: [https://ag.tavardt.com/pt/](https://ag.tavardt.com/pt/)
* **Central de Ferramentas**: [https://tools.tavardt.com/pt/](https://tools.tavardt.com/pt/)

***

## Blueprints Técnicos e Recursos Disponíveis

1. **Aplicação Web Interativa**: Diagnóstico determinístico, cálculo de postura defensiva e recomendações imediatas no navegador.
2. **Utilitário CLI Local**: Script Python determinístico executado diretamente no ambiente de produção para auditoria offline.
3. **Especificações de Segurança**: Manifestos e configurações de hardening em conformidade com as normas internacionais.

***

## Uso do Utilitário CLI Determinístico

Para executar a inspeção técnica no ambiente local:

```bash
git clone https://github.com/TAVARDT-Portugal/mcp-security-auditor-pt.git
cd mcp-security-auditor-pt
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 scanner.py -json
```

***

## Links Úteis

* **Portal Corporativo:** https://ag.tavardt.com/pt/
* **Suíte de Diagnósticos:** https://tools.tavardt.com/pt/
* **Contacto Técnico:** https://ag.tavardt.com/pt/contacto/

***

© 2026 TAVARDT Portugal. Todos os direitos reservados. Soberania e Defesa de Infraestrutura.
