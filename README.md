<div align="center">
  <h1>NetOps Assistant</h1>
  <p><strong>Plataforma web para análise, documentação e validação de configurações de equipamentos de rede</strong></p>
  <p>
    <img src="https://img.shields.io/badge/Python-3.12-blue?logo=python" alt="Python 3.12">
    <img src="https://img.shields.io/badge/Django-5.0+-green?logo=django" alt="Django 5.0+">
    <img src="https://img.shields.io/badge/Tests-1232_✔️-brightgreen" alt="1232 testes">
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
| **VRF / L3VPN** | VPN-instance (description, RD, RT import/export/both), interfaces binding, rotas estáticas VRF, BGP VPNv4 (peers, enable, route-policy), BGP ipv4-family vpn-instance (import-route, networks, CE peers, route-policy) |
| **QoS / Traffic Policy** | Traffic classifier (if-match acl/any/dscp/8021p), traffic behavior (CAR cir/pir/cbs/pbs, remark dscp, queue, statistic enable), traffic policy (classifier behavior precedence), aplicação em interface (inbound/outbound), qos-profile, qos car |
| **NAT / PAT** | Address-group (start/end IP, vpn-instance), NAT outbound (ACL, address-group, no-pat), NAT static (protocol, global/inside IP/port, vpn-instance), NAT server (protocol, global/inside IP/port), NAT ALG, aplicação em interface |
| **IPv6 / BGP IPv6** | Interfaces IPv6 (enable, address, link-local, auto, global), rotas estáticas IPv6 (global + vpn-instance), IPv6 prefix-list, BGP IPv6 unicast (peers, networks com prefix length, route-policy), VPNv6, ipv6-family vpn-instance, OSPFv3 (processos, interfaces), ISIS IPv6 (enable, cost) |
| **Circuitos** | L3 Transit, VLAN Transport, QinQ, L2VPN/VSI |
| **Serviços** | BNG/BAS, AAA, RADIUS, IP Pool, SNMP, NTP, Syslog, VTY/SSH, local-users, L2 Switching, STP/MSTP |
| **Issues** | Descrições ausentes, next-hop inalcançável, SNMP sem ACL, Telnet ativo, trunk allow all, STP desabilitado, redistribuição sem filtro, VPN-instance sem RD/RT, VRF sem interface/rota, RD duplicado, VPNv4 peer não habilitado, referência a VPN-instance inexistente, traffic-policy/classifier/behavior não encontrado, classifier/behavior/policy órfão, QoS profile não encontrado, cliente sem QoS, NAT outbound sem address-group/ACL inexistente, address-group órfão, NAT static com IP privado, NAT server expondo porta sensível, NAT server sem protocolo, NAT em interface sem descrição, NAT em VRF inexistente, ALG SIP habilitado, IPv6 address sem ipv6 enable, BGP IPv6 peer sem enable, rota IPv6 next-hop inalcançável, IPv6 default route, IPv6 prefix-list permit any, OSPFv3/ISIS IPv6 processo inexistente, VPNv6 peer sem enable, BGP ipv6-family vpn-instance inexistente, BNG/BAS issues (domain, RADIUS, AAA, pool, interface), PIM sem multicast routing-enable, IGMP sem multicast routing, MLD sem IPv6 multicast routing, PIM sem RP/BSR, IGMP version 1, PIM interface sem descrição, IGMP snooping sem querier, multicast VPN-instance inexistente, grupo IGMP/MLD inválido etc. |
| **BNG/BAS Avançado** | AAA schemes (auth/acct/authz), domínios de assinante, RADIUS server groups (auth+acct servers, shared-key cipher/simple), IP pools (local/remote, gateway, sections, DNS, lease), BAS interfaces (access-type, default-domain, authentication-method, triggers, accounting-copy, QinQ), dependency map, busca, documentação, comparação, validation/rollback plan |
| **PPPoE Server** | Virtual-Template (PPP auth-mode, keepalive, MTU/MRU, ip unnumbered, remote address pool), PPPoE server bind, max-sessions, relação PPPoE → interface BAS → Virtual-Template → domain → AAA/RADIUS/IP pool, dependency map, busca, documentação, comparação, validation/rollback plan |
| **BFD / HA** | BFD global, BFD sessions (peer-ip/ipv6, discriminators, timers, commit), BFD em BGP peers + timers, BFD em ISIS/OSPF/OSPFv3 all-interfaces e por interface, BFD em LDP, Graceful Restart (BGP/ISIS/OSPF/LDP), NSR (ISIS/BGP/OSPF), dependency map, busca, documentação, comparação, validation/rollback plan |
| **Multicast / PIM / IGMP / MLD** | Multicast routing-enable (IPv4/IPv6), PIM (global mode, static-RP, BSR candidate, RP candidate), PIM por interface (sm/dm/ssm, hello-holdtime), IGMP (enable, version, static-group, join-group, limit), MLD (enable, version, static-group), IGMP snooping (global/VLAN, version, querier), multicast em VPN-instance, dependency map, busca, documentação, comparação, validation/rollback plan |
| **Huawei VRP Avançado** | EVPN/VXLAN (VNI, bridge-domain, NVE e peers), Segment Routing MPLS/SRv6 (locator, prefix-SID e label blocks), MPLS-TE/RSVP-TE (túneis, explicit-path e tunnel-policy), CGNAT (instances, port-block, session limit e logging), MSDP, telemetria/gRPC/NetStream/sFlow e BGP avançado (RR, confederação, add-path, dampening e route-limit) |

### ZTE OLT / ZXA10 — Cobertura inicial

| Categoria | Itens detectados |
|-----------|-----------------|
| **Inventário GPON** | Portas PON (gpon-olt_*), ONUs (gpon-onu_*), ONU ID, serial, tipo, name/description e estado administrativo |
| **Serviços de cliente** | TCONT, GEMPORT, service-port, vport, user-vlan, VLAN de serviço e blocos pon-onu-mng |
| **Rede da OLT** | Uplinks gei_/xgei_, VLANs, trunks, IP de interface e rotas estáticas |
| **Busca Global** | Busca por PON, interface ONU, serial, cliente/descrição, VLAN e service-port |
| **Issues ZTE OLT** | PON sem ONU, ONU sem serial, ONU sem identificação, ONU sem service-port e service-port sem VLAN |

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

O `parsed_data`, os metadados de serviços e as telas nunca armazenam nem exibem communities SNMP, senhas de usuários locais ou secrets de autenticação; somente flags e tipos mascarados são preservados. A configuração bruta do snapshot é armazenada integralmente para auditoria e deve ser protegida por acesso restrito, criptografia e política de retenção no ambiente de produção.

---

## Testes

**1232 testes automatizados** — 0 falhas, 0 migrations pendentes (validação em 21/06/2026).

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

### Exemplos L3VPN / VRF

```bash
python manage.py analyze_config_file sample_configs/huawei_l3vpn_basic.txt --vendor huawei --device-name "NE40-L3VPN"
python manage.py analyze_config_file sample_configs/huawei_l3vpn_risky.txt --vendor huawei --device-name "NE40-L3VPN-RISK"
python manage.py compare_config_files sample_configs/huawei_l3vpn_change_before.txt sample_configs/huawei_l3vpn_change_after.txt --vendor huawei --device-name "NE40-L3VPN-DIFF"
```

### Exemplos QoS / Traffic Policy / CAR

```bash
python manage.py analyze_config_file sample_configs/huawei_qos_basic.txt --vendor huawei --device-name "NE40-QOS"
python manage.py analyze_config_file sample_configs/huawei_qos_risky.txt --vendor huawei --device-name "NE40-QOS-RISK"
python manage.py compare_config_files sample_configs/huawei_qos_change_before.txt sample_configs/huawei_qos_change_after.txt --vendor huawei --device-name "NE40-QOS-DIFF"
```

### Exemplos NAT / PAT

```bash
python manage.py analyze_config_file sample_configs/huawei_nat_basic.txt --vendor huawei --device-name "NE40-NAT"
python manage.py analyze_config_file sample_configs/huawei_nat_risky.txt --vendor huawei --device-name "NE40-NAT-RISK"
python manage.py compare_config_files sample_configs/huawei_nat_change_before.txt sample_configs/huawei_nat_change_after.txt --vendor huawei --device-name "NE40-NAT-DIFF"
```

### Exemplos IPv6 / BGP IPv6 / VPNv6

```bash
python manage.py analyze_config_file sample_configs/huawei_ipv6_basic.txt --vendor huawei --device-name "NE40-IPV6"
python manage.py analyze_config_file sample_configs/huawei_ipv6_risky.txt --vendor huawei --device-name "NE40-IPV6-RISK"
python manage.py network_search "2001:db8:100::1"
python manage.py network_search "vpnv6"
python manage.py compare_config_files sample_configs/huawei_ipv6_change_before.txt sample_configs/huawei_ipv6_change_after.txt --vendor huawei --device-name "NE40-IPV6-DIFF"
```

### Exemplos BNG / BAS

```bash
python manage.py analyze_config_file sample_configs/huawei_bng_advanced_basic.txt --vendor huawei --device-name "NE40-BNG"
python manage.py analyze_config_file sample_configs/huawei_bng_advanced_risky.txt --vendor huawei --device-name "NE40-BNG-RISK"
python manage.py network_search "cliente-pppoe"
python manage.py network_search "RAD-CLIENTES"
python manage.py network_search "POOL-CLIENTES"
python manage.py compare_config_files sample_configs/huawei_bng_advanced_change_before.txt sample_configs/huawei_bng_advanced_change_after.txt --vendor huawei --device-name "NE40-BNG-DIFF"
```

### Exemplos PPPoE Server / Virtual-Template

```bash
python manage.py analyze_config_file sample_configs/huawei_pppoe_basic.txt --vendor huawei --device-name "NE40-PPPOE"
python manage.py analyze_config_file sample_configs/huawei_pppoe_risky.txt --vendor huawei --device-name "NE40-PPPOE-RISK"
python manage.py network_search "pppoe"
python manage.py network_search "Virtual-Template1"
python manage.py compare_config_files sample_configs/huawei_pppoe_change_before.txt sample_configs/huawei_pppoe_change_after.txt --vendor huawei --device-name "NE40-PPPOE-DIFF"
```

### Exemplos Multicast / PIM / IGMP / MLD

```bash
python manage.py analyze_config_file sample_configs/huawei_multicast_basic.txt --vendor huawei --device-name "NE40-MCAST"
python manage.py analyze_config_file sample_configs/huawei_multicast_risky.txt --vendor huawei --device-name "NE40-MCAST-RISK"
python manage.py network_search "multicast"
python manage.py network_search "pim"
python manage.py compare_config_files sample_configs/huawei_multicast_change_before.txt sample_configs/huawei_multicast_change_after.txt --vendor huawei --device-name "NE40-MCAST-DIFF"
```

### Exemplos BFD / HA / Graceful Restart / NSR

```bash
python manage.py analyze_config_file sample_configs/huawei_ha_bfd_basic.txt --vendor huawei --device-name "NE40-HA-BFD"
python manage.py analyze_config_file sample_configs/huawei_ha_bfd_risky.txt --vendor huawei --device-name "NE40-HA-BFD-RISK"
python manage.py network_search "bfd"
python manage.py network_search "graceful-restart"
python manage.py network_search "nsr"
```

### Exemplos de busca

```bash
python manage.py network_search "CLIENTE-A"               # VPN-instance
python manage.py network_search "65000:100"                # RD ou RT
python manage.py network_search "vpn-instance"             # Todas VPN-instances
python manage.py network_search "vpnv4"                    # Peers VPNv4
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
python manage.py network_search "cliente-pppoe"            # Domínio de assinante BNG
python manage.py network_search "RAD-CLIENTES"            # RADIUS group BNG
python manage.py network_search "POOL-CLIENTES"           # IP pool BNG
python manage.py network_search "pppoe"                   # PPPoE / Virtual-Template
python manage.py network_search "Virtual-Template1"       # Virtual-Template específica
python manage.py network_search "bfd"                     # BFD / Fast Convergence
python manage.py network_search "graceful-restart"        # Graceful Restart
python manage.py network_search "nsr"                     # NSR / Non-Stop Routing
python manage.py network_search "multicast"               # Multicast routing
python manage.py network_search "pim"                     # PIM / RP / BSR
python manage.py network_search "239.1.1.1"               # Grupo IGMP específico
python manage.py network_search "ff3e::1"                 # Grupo MLD específico
python manage.py compare_config_files sample_configs/huawei_ha_bfd_change_before.txt sample_configs/huawei_ha_bfd_change_after.txt --vendor huawei --device-name "NE40-HA-BFD-DIFF"
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
| **Fechamento Huawei MVP** | ✔ BGP, policies, ACLs, OSPF, **ISIS, MPLS/LDP, VRF/L3VPN, QoS/Traffic Policy/CAR, NAT/PAT, IPv6/BGP IPv6/VPNv6/OSPFv3/ISIS IPv6, BNG/BAS, PPPoE, BFD/HA, multicast, EVPN/VXLAN, Segment Routing/SRv6, MPLS-TE, CGNAT, MSDP, telemetria e BGP avançado**, diff, documentação, busca, suíte com 1232 testes |
| **Inventário e Snapshots** | Cadastro de devices, upload de configs, versões |
| **Produção** | Docker, deploy, autenticação, permissões, backup |
| **Mapa Físico/Lógico** | PoPs, OLTs, DIOs, fibras, CTOs, clientes no mapa |
| **Cobertura Huawei Avançada** | EVPN/VXLAN, Segment Routing/SRv6, MPLS-TE/RSVP-TE, CGNAT, MSDP, telemetria/streaming e BGP avançado |
| **Multi-vendor** | Huawei/VRP, ZTE OLT/ZXA10, Cisco em pausa, Datacom planejado |
| **Automação Assistida** | Pré-check, pós-check, templates com aprovação |

---

## Licença

Proprietário — Uso interno.

---

<div align="center">
  <sub>Desenvolvido para operação de rede ISP — do BGP ao cliente final.</sub>
</div>
