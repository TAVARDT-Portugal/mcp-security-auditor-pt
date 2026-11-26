<p align="center">
  <a href="https://ag.tavardt.com/pt/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Auditor de Segurança para Model Context Protocol (MCP)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-portugal.github.io/mcp-security-auditor-pt/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Auditor de segurança de configuração e mecanismo automatizado de blindagem para servidores Model Context Protocol (MCP) e agentes de IA projetado pela **TAVARDT**. Avalia manifestos de clientes contra interpretadores shell diretos, montagens perigosas de volumes, credenciais em texto puro, dependências sem versão e vetores SSRF contra metadados de nuvem.

***

## Capacidades Centrais e Arquitetura Defensiva

* **Verificação de Menor Privilégio**: Audita definições de servidores em configurações de agentes de IA contra limites estritos de segurança zero-trust.
* **Blindagem Automatizada de Configurações**: Gera manifestos corrigidos que isolam comandos shell em contêineres de leitura e abstraem credenciais em variáveis de ambiente.
* **Integração Flexível a Pipelines**: Funciona perfeitamente como auditor de linha de comando local, barreira de validação em CI/CD com código de saída estrito ou gerador de relatórios JSON.

***

## Vetores de Risco e Impacto Operacional

Configurações irrestritas de servidores MCP expõem o sistema operacional hospedeiro e dados locais a movimentação lateral, roubo de informações e execução remota não autorizada. O scanner intercepta seis vetores distintos de vulnerabilidade para proteger ecossistemas de agentes autônomos:

* **Execução Direta de Interpretadores Shell (`Execução de Comandos`)**: Detecta shells como bash, powershell ou cmd executando diretamente sem isolamento em contêineres (-35 pontos de penalidade, CRÍTICO).
* **Flags de Execução Dinâmica de Código (`Execução de Comandos`)**: Identifica modificadores de execução arbitrária como -c, /c, invoke-expression ou eval dinâmico (-25 pontos de penalidade, CRÍTICO).
* **Montagem de Raiz e Diretórios Sensíveis (`Acesso a Arquivos`)**: Bloqueia montagens irrestritas do sistema de arquivos (-35 pontos) e acesso a pastas protegidas como chaves SSH, credenciais AWS e diretórios de sistema (-30 pontos de penalidade, CRÍTICO).
* **Credenciais e Chaves em Texto Puro (`Segredos Expostos`)**: Mapeia senhas de banco de dados e tokens privados de API armazenados sem referência a variáveis de ambiente (-20 pontos de penalidade, ALTO).
* **Tentativas de SSRF contra Metadados de Nuvem (`Segurança de Rede`)**: Intercepta argumentos direcionados a endpoints de instâncias de nuvem e serviços de metadados internos (-20 pontos de penalidade, ALTO).
* **Execução de Pacotes Remotos sem Versão Fixa (`Segurança da Cadeia de Suprimentos`)**: Identifica chamadas npx, uvx ou pipx sem tags imutáveis de versão (-10 pontos de penalidade, MÉDIO).

A pontuação de segurança inicia em 100 pontos e decresce conforme as não conformidades localizadas. Zero apontamentos reflete conformidade integral com o princípio do menor privilégio, enquanto achados críticos disparam interrupção imediata em esteiras automatizadas.

***

## Instalação e Execução CLI

Audite configurações localmente ou integre barreiras de validação em esteiras automatizadas utilizando suporte nativo em Python:

```bash
# Clonar o repositório oficial
git clone https://github.com/TAVARDT-Portugal/mcp-security-auditor-pt.git

# Acessar o diretório de trabalho
cd mcp-security-auditor-pt

# Auditar um arquivo de configuração MCP
python mcp_security_scanner.py -f mcp.json

# Executar em modo estrito de validação
python mcp_security_scanner.py -f mcp.json -s

# Gerar configuração blindada e emitir relatório JSON
python mcp_security_scanner.py -f mcp.json -o hardened_mcp.json -j
```

***

## FAQ Técnico

### Quais vetores de vulnerabilidade são avaliados pelo auditor em configurações MCP?

O utilitário examina manifestos contra execução direta de interpretadores shell, flags de comando dinâmico, montagem irrestrita de sistemas de arquivos, credenciais expostas, pacotes remotos sem versão fixa e acessos SSRF a metadados de nuvem. Cada não conformidade identificada aplica deduções ponderadas sobre uma pontuação defensiva inicial de 100 pontos.

### Como a ferramenta mitiga riscos de escalada de privilégios em montagens de diretórios?

O auditor identifica montagens de diretório raiz e acessos a pastas protegidas como chaves SSH, credenciais AWS e diretórios de sistema operacional sob severidade crítica. A higienização executada com a opção -o redireciona os caminhos para volumes de sandbox isolados sob o princípio do menor privilégio.

### Por que argumentos dinâmicos como -c ou chamadas de avaliação arbitrária são considerados críticos?

O uso de parâmetros dinâmicos de execução possibilita que agentes de IA ou entradas hostis processem comandos arbitrários no sistema operacional anfitrião. A restrição preventiva desses modificadores garante que as ferramentas processem apenas binários estritamente parametrizados sem avaliação de código arbitrário.

### De que forma o recurso de blindagem automatizada protege segredos e tokens expostos?

A rotina de auto-harden ativada pelo parâmetro -o substitui strings de conexão e chaves de API em texto puro por referências parametrizadas a variáveis de ambiente do host. Essa abstração impede que dados confidenciais de autenticação sejam gravados em arquivos de repositório ou logs compartilhados de agentes.

### O auditor pode ser utilizado para controle de conformidade em esteiras de CI/CD?

A ferramenta CLI processa arquivos de configuração locais através do parâmetro -f e oferece o modo estrito -s para interromper a execução com código de saída 1 perante desvios. A emissão de dados estruturados com a flag -j viabiliza a integração imediata a rotinas de validação contínua e governança de software.

***

## Links Úteis

* **Portal Corporativo:** https://ag.tavardt.com/pt/
* **Suíte de Diagnósticos:** https://tools.tavardt.com/pt/
* **Contacto Técnico:** https://ag.tavardt.com/pt/contacto/

***

### Licença
Distribuído sob a Licença MIT. Consulte [LICENSE](LICENSE) para obter detalhes completos.

***

© 2026 TAVARDT. Todos os direitos reservados.
