<div align="center">
  <h1>NetOps Assistant</h1>
  <p><strong>Plataforma web para análise, documentação e validação de configurações de equipamentos de rede</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Python-3.12-blue?logo=python" alt="Python 3.12">
    <img src="https://img.shields.io/badge/Django-5.0+-green?logo=django" alt="Django 5.0+">
    <img src="https://img.shields.io/badge/Tests-722_✔️-brightgreen" alt="722 testes">
    <img src="https://img.shields.io/badge/License-Proprietary-red" alt="License">
    <img src="https://img.shields.io/badge/Status-Development-yellow" alt="Status">
  </p>
  <p>
    <a href="#funcionalidades">Funcionalidades</a> •
    <a href="#começando">Começando</a> •
    <a href="#comandos-cli">CLI</a> •
    <a href="#arquitetura">Arquitetura</a> •
    <a href="#roadmap">Roadmap</a>
  </p>
</div>

---

NetOps Assistant é uma ferramenta web para equipes de ISP que precisam **analisar, documentar e validar** configurações de equipamentos de rede com mais velocidade e segurança. O foco inicial é **Huawei/VRP (NE40)**, com suporte inicial **Cisco IOS/IOS-XE** e arquitetura preparada para expansão.

O sistema interpreta configurações de roteadores e switches, extrai blocos estruturados, detecta circuitos, serviços e issues, gera documentação automática em português e permite comparar versões antes/depois de mudanças.

---

## Funcionalidades

### Huawei/VRP — Cobertura principal

| Categoria | Itens detectados |
|-----------|-----------------|
| **Interfaces** | Físicas, subinterfaces dot1q, VLANs, Eth-Trunk, L2 (access/trunk/hybrid) |
| **Roteamento** | Rotas estáticas, BGP (peers, peer groups, networks), **OSPF** (processos, áreas, redes, redistribuição), **ISIS** (processos, network-entity, circuit-type, cost, autenticação) |
| **MPLS / LDP** | MPLS global (LSR-ID, TE), MPLS LDP (transporte, graceful-restart, remote-peers, interface enable) |
| **Políticas e Filtros** | Route-policy, ip-prefix, ACL (básica/expandida), as-path-filter, community-filter, dependency map BGP → policy |
| **Circuitos** | L3 Transit, VLAN Transport, QinQ, L2VPN/VSI |
| **Serviços** | BNG/BAS, AAA, RADIUS, IP Pool, SNMP, NTP, Syslog, VTY/SSH, local-users, L2 Switching, STP/MSTP |
| **Issues** | Descrições ausentes, next-hop inalcançável, SNMP sem ACL, Telnet ativo, trunk allow all, STP desabilitado, redistribuição sem filtro, etc. |

### Cisco IOS/IOS-XE — Suporte inicial

| Categoria | Itens detectados |
|-----------|-----------------|
| **Hostname**, interfaces físicas e subinterfaces dot1q, rotas estáticas (global + VRF) |
| **BGP** (peers, route-maps, networks, update-source) |
| **Detecção de circuito L3** |
| **Busca técnica global** e comparação de snapshots |

### Interface Web

- **Dashboard** — estatísticas, análises recentes, dispositivos em atenção
- **Nova Análise** — cole ou envie uma configuração e receba resultado estruturado
- **Resultado da Análise** — cards de resumo, circuitos, serviços e issues
- **Documentação Automática** — documentação técnica em português com funções, mapa lógico, interfaces, BGP, circuitos, issues e recomendações
- **Busca Global** — busque por interface, IP, prefixo, VLAN, ASN, policy, texto livre com filtros por vendor e dispositivo
- **Comparação** — compare duas versões de configuração com diff estruturado e explicação de impacto

### CLI (Command Line)

```bash
python manage.py analyze_config_file config.txt --vendor huawei --device-name "MEU-ROTEADOR"
python manage.py network_search "EXPORT-CLIENTE"
python manage.py compare_config_files before.txt after.txt --vendor huawei --device-name "MEU-DIFF"
```

### Segurança

O sistema **nunca armazena** communities SNMP, senhas de usuários locais ou secrets de autenticação. Apenas flags e evidências mascaradas são preservadas.

---

## Testes

**722 testes automatizados** — 0 falhas, 0 migrations pendentes.

```bash
# Todos os testes
python manage.py test

# Por módulo
python manage.py test apps.parsers.huawei.tests    # Parser Huawei
python manage.py test apps.parsers.cisco.tests     # Parser Cisco
python manage.py test apps.analysis.tests          # Análise completa
python manage.py test apps.analysis.tests.test_policy_integration  # Políticas + OSPF
```

---

## Começando

### Pré-requisitos

- Python 3.12+
- Pip

### Instalação

```bash
# Clone
git clone https://github.com/katoonnoass/netops-assistant.git
cd netops-assistant

# Ambiente virtual
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux

# Dependências
pip install -r requirements.txt

# Configuração
copy .env.example .env      # Windows
# cp .env.example .env      # Linux

# Migrações
python manage.py migrate

# Iniciar servidor
python manage.py runserver
```

Acesse: **http://127.0.0.1:8000**

### Exemplo rápido

```bash
python manage.py analyze_config_file sample_configs/huawei_l3_transit_public_prefix.txt --vendor huawei --device-name "ROTEADOR-TESTE"
```

Saída:
```
Equipamento: ROTEADOR-TESTE (huawei)
Snapshot #1 criado (320 bytes)
Executando análise...

=== RESUMO DA ANÁLISE ===
  ParsedConfig #:           1
  Interfaces detectadas:    1
  Rotas estáticas:          1
  Circuitos detectados:     1
  Issues encontradas:       0

--- Circuitos ---
  [Trânsito L3] Eth-Trunk100.1234 (local: 10.255.123.1 -> remote: 10.255.123.2)
    Prefixo roteado: 200.200.200.0/30
```

### Pelo navegador

1. Acesse **http://127.0.0.1:8000/configs/new/**
2. Cole a configuração de exemplo (`sample_configs/huawei_l3_transit_public_prefix.txt`)
3. Informe o nome do equipamento e clique em **Analisar Configuração**
4. Navegue pelos resultados, documentação automática e busca

---

## Comandos CLI

| Comando | Descrição |
|---------|-----------|
| `python manage.py analyze_config_file <arquivo> --vendor <vendor> --device-name <nome>` | Analisar arquivo de configuração |
| `python manage.py analyze_snapshot <id>` | Reanalisar snapshot existente |
| `python manage.py network_search <termo>` | Busca técnica global |
| `python manage.py compare_config_files <antes> <depois> --vendor <v> --device-name <n>` | Comparar dois arquivos |
| `python manage.py compare_snapshots <id1> <id2>` | Comparar dois snapshots no banco |

### Exemplos de busca

```bash
python manage.py network_search "EXPORT-CLIENTE"          # Route-policy + dependência BGP
python manage.py network_search "CLIENTE-X"                # IP prefix
python manage.py network_search "200.200.200.0/30"         # Prefixo em rotas/policies
python manage.py network_search "acl 3001"                 # ACL
python manage.py network_search "as-path-filter 10"        # AS-path filter
python manage.py network_search "community-filter 20"      # Community filter
python manage.py network_search "65000:100"                # Community value
python manage.py network_search "vlan 1234"                # VLAN em interfaces/circuitos
python manage.py network_search "Eth-Trunk100.1234"        # Interface específica
python manage.py network_search "isis"                     # ISIS configuração
python manage.py network_search "mpls"                     # MPLS / LDP
python manage.py network_search "network-entity"           # Network-entity ISIS
```

---

## Arquitetura

```
netops_assistant/
├── manage.py
├── netops_assistant/          # Config Django (settings, urls, wsgi)
├── apps/
│   ├── core/                  # Dashboard, comparações
│   ├── devices/               # Cadastro de equipamentos
│   ├── config_archive/        # Snapshots de configuração
│   ├── parsers/               # Parsers por fabricante
│   │   ├── huawei/            # Huawei/VRP (completo)
│   │   └── cisco/             # Cisco IOS/IOS-XE (inicial)
│   └── analysis/              # Detecção, busca, documentação
├── templates/                 # Django Templates
├── static/css/app.css         # Estilos
├── sample_configs/            # 36 configurações de exemplo
└── docs/                      # Documentação do projeto
```

### Stack

| Camada | Tecnologia |
|--------|-----------|
| Backend | Python + Django 5.0+ |
| API | Django REST Framework (instalado, futura expansão) |
| Banco | SQLite (dev) / PostgreSQL (prod) |
| Parser | Python puro — determinístico, sem IA |
| Frontend | Django Templates + CSS puro |

### Fluxo de análise

```
ConfigSnapshot (config bruta)
       │
       ▼
  Parser (Huawei/VRP, Cisco IOS)
       │
       ▼
  ParsedConfig (JSON estruturado)
       │
       ├──► Detectores de Circuitos (L3, VLAN, QinQ, L2VPN)
        ├──► Detectores de Serviços (BNG, AAA, RADIUS, OSPF, ISIS, MPLS, LDP, SNMP, NTP, STP...)
       └──► Detectores de Issues/Riscos (descrição, next-hop, SNMP, switching...)
```

O fluxo é **idempotente** — reanalisar o mesmo snapshot não duplica registros.

---

## Roadmap

| Fase | Objetivo |
|------|----------|
| **Fechamento Huawei MVP** | ✔ BGP, policies, ACLs, OSPF, **ISIS, MPLS/LDP**, diff, documentação, 722 testes |
| **Inventário e Snapshots** | Cadastro de devices, upload de configs, versões |
| **Produção** | Docker, deploy, autenticação, permissões, backup |
| **Mapa Físico/Lógico** | PoPs, OLTs, DIOs, fibras, CTOs, clientes no mapa |
| **Cobertura Huawei Avançada** | VPNv4/L3VPN, QoS, NAT, IPv6 |
| **Multi-vendor** | Cisco completo, ZTE, Datacom |
| **Automação Assistida** | Pré-check, pós-check, templates com aprovação |

---

## Licença

Proprietário — Uso interno.

---

<div align="center">
  <sub>Desenvolvido para operação de rede ISP — do BGP ao cliente final.</sub>
</div>
