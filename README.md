# 🐍 Python Network Sniffer (sniffer_pro.py)

![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg)

Um sniffer de rede em Python leve e personalizável, projetado para capturar, decodificar e analisar pacotes de rede em tempo real. Esta ferramenta oferece uma alternativa transparente e flexível às soluções comerciais, ideal para aprendizado, auditoria de segurança e monitoramento de tráfego de rede.

## ✨ Funcionalidades

*   **Captura de Pacotes Brutos**: Intercepta pacotes diretamente da interface de rede.
*   **Decodificação de Cabeçalhos IP**: Extrai detalhes como versão, IHL, TOS, TTL, e endereços IP de origem/destino.
*   **Suporte a Múltiplos Protocolos**: Decodificação básica para ICMP, TCP e UDP, exibindo informações relevantes (tipo/código ICMP, portas de origem/destino TCP/UDP).
*   **Detecção Automática de IP Local**: Simplifica a inicialização, detectando automaticamente o IP da interface de rede ou solicitando a entrada do usuário.
*   **Registro de Eventos (Logging)**: Opção para salvar o tráfego capturado em um arquivo de log com timestamps precisos.
*   **Relatório Estatístico Detalhado**: Ao finalizar a captura (via `Ctrl+C`), gera um relatório consolidado no terminal, incluindo:
    *   Total de pacotes capturados.
    *   Distribuição percentual por protocolo.
    *   Top 5 IPs de origem e destino, para identificar padrões de comunicação.
*   **Portabilidade**: Compatível com sistemas operacionais Windows e Linux.
*   **Tratamento de Erros**: Gerenciamento robusto de exceções para permissões e interrupções.

## 🚀 Instalação

1.  **Clone o repositório (ou baixe o arquivo `sniffer_pro.py`):**
    ```bash
    git clone https://github.com/seu-usuario/seu-repositorio.git # Substitua pelo seu repositório
    cd seu-repositorio
    ```

2.  **Certifique-se de ter Python 3.x instalado.**

3.  **Não há dependências externas além das bibliotecas padrão do Python.**

## 💡 Como Usar

Para executar o sniffer, você precisará de permissões de administrador/root, pois ele acessa a camada de rede diretamente.

Abra seu terminal ou prompt de comando e navegue até o diretório onde o `sniffer_pro.py` está salvo.

```bash
python sniffer_pro.py [IP_LOCAL] [arquivo_log]
```

*   `<IP_LOCAL>`: O endereço IP da interface de rede que você deseja monitorar. **Se omitido, o script tentará detectar automaticamente o IP local e perguntará se você deseja usá-lo.**
*   `[arquivo_log]`: (Opcional) O caminho para um arquivo onde o tráfego capturado será salvo. Se omitido, o tráfego será exibido apenas no console.

### Exemplos de Uso:

1.  **Iniciar o sniffer e usar o IP detectado automaticamente (recomendado para a maioria dos casos):**
    ```bash
    python sniffer_pro.py
    ```
    *O script perguntará se você deseja usar o IP detectado. Pressione `Enter` para confirmar ou digite outro IP.* 

2.  **Iniciar o sniffer em um IP específico e exibir no console:**
    ```bash
    python sniffer_pro.py 192.168.1.100
    ```

3.  **Iniciar o sniffer em um IP específico e salvar o tráfego em um arquivo de log:**
    ```bash
    python sniffer_pro.py 192.168.1.100 traffic_log.txt
    ```

4.  **Iniciar o sniffer, usar o IP detectado e salvar em log:**
    ```bash
    python sniffer_pro.py traffic_log.txt
    ```
    *Neste caso, o script ainda perguntará sobre o IP local, e o `traffic_log.txt` será o arquivo de log.*

### Parando a Captura e Visualizando o Relatório

Para parar a captura de pacotes e visualizar o relatório estatístico final, pressione `Ctrl+C` no terminal. O relatório será exibido imediatamente, sumarizando a atividade da rede durante a sessão de captura.

## 📊 Relatório Estatístico de Exemplo

```
==================================================
           RELATÓRIO FINAL DE CAPTURA
==================================================
Início: 2026-04-08 10:00:00
Fim:    2026-04-08 10:05:30
Duração: 0:05:30.123456
--------------------------------------------------
Total de Pacotes Capturados: 1234
--------------------------------------------------
Distribuição por Protocolo:
  - TCP   :  800 (64.8%)
  - UDP   :  300 (24.3%)
  - ICMP  :  100 ( 8.1%)
  - 65535 :   34 ( 2.8%)
--------------------------------------------------
Top 5 IPs de Origem:
  - 192.168.1.100: 500 pacotes
  - 8.8.8.8      : 200 pacotes
  - 172.217.0.1  : 150 pacotes
  - 10.0.0.5     : 100 pacotes
  - 192.168.1.1   : 80 pacotes
--------------------------------------------------
Top 5 IPs de Destino:
  - 8.8.8.8      : 450 pacotes
  - 192.168.1.100: 300 pacotes
  - 142.250.0.1  : 120 pacotes
  - 10.0.0.1     : 90 pacotes
  - 192.168.1.1   : 70 pacotes
==================================================
```

## 🆚 Comparativo com Sniffers de Mercado

Enquanto ferramentas como Wireshark, tcpdump e Fiddler são poderosas e amplamente utilizadas, este sniffer personalizado em Python oferece vantagens significativas em certos contextos, especialmente para quem busca transparência, flexibilidade e integração em projetos específicos.

| Característica / Ferramenta | Sniffer Personalizado (Python) | Wireshark / tcpdump | Fiddler |
| :-------------------------- | :----------------------------- | :------------------ | :------ |
| **Flexibilidade e Personalização** | Alta. Código totalmente modificável para atender requisitos específicos. | Média. Extensível via plugins/scripts, mas a lógica central é fixa. | Média. Extensível via scripts, focado em HTTP/HTTPS. |
| **Transparência** | Total. Cada linha de código é visível e compreensível. | Baixa. Binários compilados, difícil auditar o funcionamento interno. | Baixa. Binários compilados. |
| **Curva de Aprendizagem** | Média/Alta (requer conhecimento de Python e redes). | Média (GUI intuitiva, mas filtros complexos exigem conhecimento). | Baixa (GUI intuitiva, focado em web). |
| **Recursos de Análise** | Básicos a Moderados (com relatório estatístico). Requer desenvolvimento adicional para análises complexas. | Avançados (análise profunda de protocolos, estatísticas, reconstrução de sessões). | Avançados (focado em HTTP/HTTPS, depuração de tráfego web). |
| **Geração de Relatórios** | Sumário estatístico automático ao final da captura (protocolos, IPs). | Relatórios detalhados e personalizáveis via GUI ou linha de comando. | Relatórios focados em tráfego web e performance. |
| **Integração** | Alta. Facilmente integrável em outros scripts ou sistemas Python. | Baixa. Geralmente usado como ferramenta standalone. | Média. API para integração com .NET. |
| **Custo** | Gratuito (código aberto). | Gratuito (código aberto). | Gratuito (versão básica), pago (versão Pro). |
| **Desempenho** | Variável, depende da otimização do código. | Alto (otimizado em C/C++). | Médio (baseado em .NET). |
| **Uso Típico** | Auditoria de segurança, pesquisa, aprendizado, automação de tarefas específicas, monitoramento de IoT, **análise rápida de tendências de tráfego**. | Análise forense, depuração de rede, desenvolvimento de protocolos, educação. | Depuração de aplicações web, testes de API, análise de performance web. |

## 🤝 Contribuição

Contribuições são sempre bem-vindas! Se você tem ideias para melhorias, novas funcionalidades ou encontrou algum bug, sinta-se à vontade para:

1.  Abrir uma [Issue](https://github.com/seu-usuario/seu-repositorio/issues) descrevendo a sugestão ou o problema.
2.  Fazer um [Fork](https://github.com/seu-usuario/seu-repositorio/fork) do repositório.
3.  Criar uma nova branch para sua feature (`git checkout -b feature/MinhaNovaFeature`).
4.  Fazer suas alterações e commitar (`git commit -m 'feat: Adiciona Minha Nova Feature'`).
5.  Enviar suas alterações (`git push origin feature/MinhaNovaFeature`).
6.  Abrir um [Pull Request](https://github.com/seu-usuario/seu-repositorio/pulls).

## 📄 Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 📧 Contato

Se tiver alguma dúvida ou sugestão, entre em contato através do GitHub.
