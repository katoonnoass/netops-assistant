# NetOps Assistant

Assistente pessoal de redes — plataforma web para análise, documentação e validação de configurações de equipamentos de rede.

Inicialmente focado em equipamentos **Huawei/VRP**, com arquitetura preparada para expansão futura para **ZTE, Datacom, Cisco, MikroTik** e outros fabricantes.

## Objetivo

Permitir que engenheiros de rede colem ou enviem a saída do comando `display current-configuration` (e equivalentes de outros fabricantes) e recebam:

- Separação e organização dos blocos de configuração
- Explicação em português de cada seção
- Detecção de circuitos (L3, VLAN de transporte, QinQ, BGP, OLT, BNG, L2VPN, etc.)
- Geração de documentação técnica automática
- Geração de comandos de validação
- Futuramente: geração de novas configurações com rollback e checklist

## Arquitetura

```
netops_assistant/
├── manage.py                    # Entry point Django
├── netops_assistant/            # Configuração principal do projeto
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── apps/
│   ├── core/                    # Utilitários comuns, dashboard
│   ├── devices/                 # Cadastro de equipamentos
│   ├── config_archive/          # Snapshots de configuração
│   ├── parsers/                 # Parsers por fabricante
│   │   ├── huawei/              # Parser Huawei/VRP (completo)
│   │   └── cisco/               # Parser Cisco IOS/IOS-XE (inicial)
│   └── analysis/                # Resultados de análise e circuitos
├── templates/                   # Templates Django (interface web)
│   ├── base.html
│   ├── core/
│   ├── config_archive/
│   └── analysis/
├── static/
│   └── css/app.css              # Estilos da interface web
├── sample_configs/              # Configurações de exemplo para testes manuais
│   ├── huawei_l3_transit_public_prefix.txt
│   ├── huawei_missing_descriptions.txt
│   ├── huawei_bgp_basic.txt
│   ├── huawei_vlan_transport.txt
│   ├── huawei_qinq_transport.txt
│   ├── huawei_l2vpn_vsi.txt
│   ├── huawei_mixed_isp_services.txt
│   ├── huawei_bng_basic.txt
│   └── huawei_bng_radius_aaa.txt
├── requirements.txt
├── .env.example
└── README.md
```

### Stack

| Camada    | Tecnologia                          |
|-----------|-------------------------------------|
| Backend   | Python + Django + DRF               |
| Banco     | SQLite (dev) / PostgreSQL (prod)    |
| Parser    | Python puro (determinístico)        |
| Frontend  | Django Templates (inicial)          |

## Fluxo de Análise

O sistema implementa um pipeline determinístico de análise de configurações:

```
ConfigSnapshot (bruto)
        │
        ▼
   Parser Huawei/VRP (ou outro fabricante)
        │
        ▼
   ParsedConfig (JSON estruturado salvo no banco)
        │
        ├──► Detectores de Circuitos
        │       ├── L3 Transit (subinterface dot1q + /30 + rota estática)
        │       ├── VLAN Transport (subinterface dot1q sem IP)
        │       ├── QinQ Transport (dupla tag 802.1Q)
        │       └── L2VPN/VSI (l2 binding vsi + blocos VSI)
        │
        ├──► Detectores de Serviços
        │       ├── BNG/BAS
        │       ├── AAA
        │       ├── RADIUS
        │       └── IP Pool
        │
        ├──► Detectores L2 (Switching)
        │       ├── VLANs locais (batch + description)
        │       ├── Portas access/trunk/hybrid
        │       ├── STP/MSTP
        │       └── Riscos de switching (trunk allow all, STP disabled, etc.)
        │
        └──► Detectores de Issues/Riscos
                ├── Interface sem description
                ├── Subinterface dot1q sem description
                ├── Rota estática sem description
                ├── Peer BGP sem description
                ├── Next-hop inalcançável
                ├── SNMP/NTP/Syslog/ACL
                ├── Switching L2
                └── Trunk/VLAN/STP
```

O fluxo é **idempotente**: rodar a análise duas vezes sobre o mesmo snapshot
não duplica circuitos nem issues (registros antigos são removidos antes da
reanálise).

### Modelos

| Modelo            | Descrição                                      |
|-------------------|------------------------------------------------|
| `Device`          | Equipamento de rede (nome, vendor, IP)         |
| `ConfigSnapshot`  | Configuração bruta (raw text + metadados)      |
| `ParsedConfig`    | Resultado estruturado do parser (JSON)         |
| `DetectedCircuit` | Circuito detectado (tipo, interface, rede)     |
| `DetectedService` | Serviço detectado (BNG, AAA, RADIUS, IP Pool) |
| `AnalysisIssue`   | Problema/risco identificado (severidade, tipo) |

## Interface Web

O sistema possui uma interface web via Django Templates para facilitar o uso.

### URLs

| URL | Página | Descrição |
|-----|--------|-----------|
| `/` | Dashboard | Resumo com estatísticas e análises recentes |
| `/configs/new/` | Nova Análise | Formulário para colar configuração e analisar |
| `/configs/` | Histórico | Lista de todos os snapshots analisados |
| `/analysis/<id>/` | Resultado | Detalhes da análise com circuitos e issues |
| `/analysis/<id>/documentation/` | Documentação | Documentação automática em português |
| `/comparisons/` | Comparações | Lista de comparações realizadas |
| `/comparisons/new/` | Nova Comparação | Formulário para selecionar dois snapshots |
| `/comparisons/<id>/` | Detalhe | Diferenças, impactos e recomendações |

### Fluxo pelo navegador

1. Acesse http://127.0.0.1:8000/
2. Clique em **Nova Análise**
3. Informe o nome do equipamento, selecione Huawei/VRP
4. Cole a configuração no textarea
5. Clique em **Analisar Configuração**
6. Visualize o resultado com cards de resumo, circuitos e issues

### Documentação automática

Após analisar uma configuração, clique em **Ver documentação automática** na
página de resultado. O sistema gera uma documentação técnica estruturada em
português com:

- **Resumo geral** do equipamento
- **Funções prováveis** detectadas (BGP, agregação, transporte VLAN, etc.)
- **Mapa lógico textual** hierárquico mostrando interfaces, VLANs, rotas e BGP
- **Interfaces** documentadas com tipo, descrição, IP e explicação curta
- **Eth-Trunks** e **Subinterfaces VLAN** destacadas
- **Rotas estáticas** com análise de reachability do next-hop
- **BGP** com peers, ASNs e redes anunciadas
- **Circuitos detectados** com explicação em português do tipo L3 transit
- **Issues/riscos** encontrados
- **Recomendações operacionais** baseadas nos problemas detectados

> **Nota:** Toda a documentação é gerada deterministicamente por código Python,
> sem uso de IA. As explicações são construídas com base nos dados parseados,
> circuitos e issues.

### Detecção BNG/BAS/AAA/RADIUS

O sistema detecta funções de BNG (Broadband Network Gateway) em
configurações Huawei/VRP. A detecção é baseada em palavras-chave e blocos:

| Serviço | Como é detectado | Confiança |
|---------|-----------------|-----------|
| BNG/BAS completo | BAS + AAA + RADIUS | Alta (0.90) |
| BNG/BAS parcial | BAS + AAA (sem RADIUS) | Alta (0.80) |
| AAA | Bloco AAA + domínios + schemes | 0.60–0.85 |
| RADIUS | radius-server blocks | Alta (0.85) |
| IP Pool | ip pool blocks | Alta (0.85) |
| Acesso de assinante | BAS interfaces | 0.60–0.85 |

Para testar com configuração BNG simulada:

```bash
python manage.py analyze_config_file sample_configs/huawei_bng_radius_aaa.txt \
    --vendor huawei --device-name "NE40-BNG-TESTE"
```

> **Nota:** A detecção BNG é inicial e baseada em padrões comuns.
> Sintaxes Huawei variam muito e serão refinadas com configurações reais.

### Switching L2 / VLAN / STP

O sistema detecta configurações de switching L2 em equipamentos Huawei/VRP:
VLANs locais, portas access/trunk/hybrid, STP/MSTP e riscos associados.

#### Funcionalidades

- **VLANs** — `vlan batch`, blocos `vlan <id>` com description/name, expansão
  de ranges (`100 to 105`, `1-50`)
- **Portas L2** — `port link-type access/trunk/hybrid`, `port default vlan`,
  `port trunk allow-pass vlan`, `port trunk pvid`, `port hybrid tagged/untagged`
- **STP/MSTP** — `stp enable/disable`, `stp mode mstp/rstp`,
  `stp region-configuration`, `instance <id> vlan <list>`,
  `stp edged-port enable` por interface
- **Observabilidade** — `broadcast-suppression`, `loopback-detect`,
  `lldp enable`

#### Issues/Riscos detectados

| Código | Severidade | Descrição |
|--------|-----------|-----------|
| `l2_trunk_allow_all_vlans` | Atenção | Trunk permitindo todas as VLANs |
| `l2_trunk_port_missing_description` | Atenção | Porta trunk sem descrição |
| `l2_access_port_missing_description` | Informativo | Porta access sem descrição |
| `l2_hybrid_port_missing_description` | Atenção | Porta hybrid sem descrição |
| `l2_stp_disabled_on_trunk` | Crítico | STP desabilitado em trunk |
| `l2_edge_port_on_trunk` | Atenção | Edge-port configurado em trunk |
| `l2_vlan_used_not_defined` | Atenção | VLAN usada mas não definida |
| `l2_vlan_defined_unused` | Informativo | VLAN definida sem uso detectado |

#### Exemplos CLI

```powershell
# Analisar configuração com switching L2
python manage.py analyze_config_file sample_configs/huawei_switching_l2.txt --vendor huawei --device-name "SW-HUAWEI-L2"

# Analisar configuração com riscos de switching
python manage.py analyze_config_file sample_configs/huawei_switching_risky.txt --vendor huawei --device-name "SW-HUAWEI-RISCO"

# Buscar VLANs, STP, portas
python manage.py network_search "vlan 10"
python manage.py network_search "trunk"
python manage.py network_search "stp"
python manage.py network_search "REDE-METRO"

# Analisar config com Eth-Trunk members
python manage.py analyze_config_file sample_configs/huawei_switching_ethtrunk_members.txt --vendor huawei --device-name "SW-ETH-TRUNK"

# Analisar config com VLAN usage (access, subinterface, QinQ, L2VPN)
python manage.py analyze_config_file sample_configs/huawei_switching_vlan_usage.txt --vendor huawei --device-name "SW-VLAN-USAGE"

# Buscar VLAN de subinterface, QinQ, L2VPN
python manage.py network_search "vlan 1234"
python manage.py network_search "vlan 3000"
python manage.py network_search "vlan 4000"

# Comparar before/after switching (inclui VLANs, STP, Eth-Trunk members)
python manage.py compare_config_files sample_configs/huawei_switching_change_before.txt sample_configs/huawei_switching_change_after.txt --vendor huawei --device-name "SW-L2-DIFF"

### Exemplos de Políticas de Roteamento

```bash
# Analisar config com políticas básicas (BGP peer + route-policy + ip-prefix + ACL)
python manage.py analyze_config_file sample_configs/huawei_policy_basic.txt --vendor huawei --device-name "NE40-POLICY"

# Analisar config com riscos de políticas (permit any, policy órfã, etc.)
python manage.py analyze_config_file sample_configs/huawei_policy_risky.txt --vendor huawei --device-name "NE40-POLICY-RISK"

# Buscar route-policy, ip-prefix ou ACL
python manage.py network_search "EXPORT-CLIENTE"
python manage.py network_search "CLIENTE-X"
python manage.py network_search "acl 3001"

# Buscar as-path-filter, community-filter ou valor
python manage.py network_search "as-path-filter 10"
python manage.py network_search "community-filter 20"
python manage.py network_search "65000:100"

# Comparar before/after de políticas de roteamento
python manage.py compare_config_files sample_configs/huawei_policy_change_before.txt sample_configs/huawei_policy_change_after.txt --vendor huawei --device-name "NE40-POLICY-DIFF"
```
```

### Arquivos de exemplo

A pasta `sample_configs/` contém configurações Huawei de exemplo para
testes manuais:

| Arquivo | Descrição |
|---------|-----------|
| `huawei_l3_transit_public_prefix.txt` | Circuito L3 com prefixo público e BGP |
| `huawei_missing_descriptions.txt` | Interfaces e rotas sem descrição |
| `huawei_bgp_basic.txt` | Configuração BGP básica com peers e redes |
| `huawei_vlan_transport.txt` | Transporte VLAN simples (subinterface sem IP) |
| `huawei_qinq_transport.txt` | Transporte QinQ com dupla tag 802.1Q |
| `huawei_l2vpn_vsi.txt` | L2VPN com VSI e peers VPLS |
| `huawei_mixed_isp_services.txt` | Configuração mista com L3, VLAN, QinQ e L2VPN |
| `huawei_bng_basic.txt` | BNG básico com AAA, domain e BAS PPPoE/IPoE |
| `huawei_bng_radius_aaa.txt` | BNG completo com RADIUS, AAA, pools e BGP |
| `huawei_search_demo.txt` | Configuração de demonstração para busca técnica (VLAN, Eth-Trunk, BGP, RADIUS, VSI, IP pool) |
| `huawei_switching_l2.txt` | Switching L2 com VLANs, access/trunk/hybrid, STP/MSTP |
| `huawei_switching_risky.txt` | Config com riscos de switching (trunk allow all, STP disabled, etc.) |
| `huawei_switching_change_before.txt` | Before para teste de comparação de switching |
| `huawei_switching_change_after.txt` | After para teste de comparação de switching |
| `huawei_switching_ethtrunk_members.txt` | Eth-Trunk com membros físicos e subinterface L3 |
| `huawei_switching_vlan_usage.txt` | VLANs usadas em access, trunk, subinterface, QinQ, L2VPN e STP |
| `huawei_policy_basic.txt` | BGP peer + route-policy + ip-prefix + ACL |
| `huawei_policy_risky.txt` | Config com riscos de políticas (permit any, policy orfa) |
| `huawei_policy_full_visual.txt` | Config completa com BGP + route-policy + ip-prefix + ACL + as-path + community |
| `cisco_ios_l3_transit.txt` | Circuito L3 Cisco com subinterface dot1Q, /30, rota estática e BGP |
| `cisco_ios_bgp_basic.txt` | BGP Cisco básico com peers, route-maps e networks |
| `cisco_ios_change_before.txt` | Cisco antes da mudança (para teste de comparação) |
| `cisco_ios_change_after.txt` | Cisco depois da mudança (description alterada, rota adicionada, peer alterado) |

Para testar, abra um dos arquivos, copie o conteúdo e cole no formulário
em http://127.0.0.1:8000/configs/new/. Ou use o comando CLI:

```bash
python manage.py analyze_config_file sample_configs/huawei_mixed_isp_services.txt --vendor huawei --device-name "NE40-MIXED-TESTE"
```

## Comandos de gerenciamento

### Analisar snapshot existente pelo ID

```bash
python manage.py analyze_snapshot <snapshot_id>
```

Exemplo:
```bash
python manage.py analyze_snapshot 1
```

### Analisar arquivo de configuração diretamente

```bash
python manage.py analyze_config_file <caminho_do_arquivo> --vendor huawei --device-name "MEU-ROTEADOR"
```

Exemplo com fixture existente:
```bash
python manage.py analyze_config_file apps/parsers/huawei/tests/fixtures/sample_config.txt --vendor huawei --device-name "NE40-TESTE"
```

### Como criar um snapshot via admin

1. Acesse http://127.0.0.1:8000/admin/
2. Faça login com o superusuário (crie com `python manage.py createsuperuser`)
3. Navegue até *Config archive > Snapshots de configuração*
4. Clique em *Adicionar snapshot de configuração*
5. Cole a configuração no campo *Configuração bruta*
6. Selecione o fabricante (ex: *huawei*)
7. Salve
8. Execute `python manage.py analyze_snapshot <id_do_snapshot>`

### Exemplo de configuração Huawei e saída esperada

Configuração de entrada (`config.txt`):
```huawei
#
sysname ROTEADOR-TRANSITO
#
interface Eth-Trunk100.1234
 description CLIENTE-X-TRANSITO-MKT
 vlan-type dot1q 1234
 ip address 10.255.123.1 255.255.255.252
#
ip route-static 200.200.200.0 255.255.255.252 10.255.123.2
#
return
```

Saída do comando:
```
$ python manage.py analyze_config_file config.txt --vendor huawei --device-name "ROTEADOR-TRANSITO"

Equipamento: ROTEADOR-TRANSITO (huawei)
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

### Interpretação dos resultados

O detector de circuitos L3 identifica o padrão:

1. **Subinterface** com `vlan-type dot1q` e IP /30
2. **Rota estática** apontando para um next-hop dentro da mesma rede /30
3. Se a rota aponta para uma rede **diferente** do /30 de trânsito, essa rede
   é registrada como `routed_prefix`
4. O circuito recebe confidence **0.80**

As issues detectadas incluem:

| Código                              | Severidade | Descrição                           |
|-------------------------------------|------------|-------------------------------------|
| `interface_missing_description`     | Informativo| Interface física sem descrição      |
| `subinterface_missing_description`  | Atenção    | Subinterface dot1q sem descrição    |
| `static_route_missing_description`  | Atenção    | Rota estática sem descrição         |
| `bgp_peer_missing_description`      | Atenção    | Peer BGP sem descrição              |
| `static_route_unreachable_next_hop` | Crítico    | Next-hop sem rede diretamente conectada|

## Suporte Cisco IOS/IOS-XE (Inicial)

O sistema possui suporte **inicial** para configurações Cisco IOS/IOS-XE
(`show running-config`). Huawei continua sendo o foco principal com parser
mais completo, mas o parser Cisco cobre os principais casos de uso.

### Funcionalidades Cisco atuais

- **Hostname** — extraído do comando `hostname`
- **Interfaces físicas** — GigabitEthernet, Loopback, Null, etc.
- **Subinterfaces dot1Q** — `encapsulation dot1Q <vlan>` com IP
- **Rotas estáticas** — `ip route <dest> <mask> <next-hop>` e `ip route vrf`
- **BGP básico** — `router bgp`, peers, route-maps (in/out), update-source,
  networks, password (apenas flag, senha nunca salva)
- **Detecção de circuito L3** — subinterface /30 + rota estática = trânsito L3
- **Busca técnica global** — interfaces, VLANs, IPs, ASNs, route-maps
- **Comparação de snapshots** — before/after Cisco
- **Documentação automática** — em português com funções Cisco específicas

### Cisco NÃO cobre (nesta versão)

- QinQ, L2VPN, VPLS
- BGP em VRF, address-family vpnv4
- OSPF, EIGRP, ISIS
- VLANs locais, STP, EtherChannel
- BNG/AAA/RADIUS Cisco
- Aplicação de configuração (nenhum equipamento)

### Como testar Cisco

```bash
# Analisar configuração Cisco com circuito L3
python manage.py analyze_config_file sample_configs/cisco_ios_l3_transit.txt \
    --vendor cisco_ios --device-name "CISCO-TESTE"

# Buscar interface Cisco
python manage.py network_search "GigabitEthernet0/0.1234"

# Comparar before/after Cisco
python manage.py compare_config_files sample_configs/cisco_ios_change_before.txt \
    sample_configs/cisco_ios_change_after.txt \
    --vendor cisco_ios --device-name "CISCO-DIFF"
```

### Exemplo de configuração Cisco e saída esperada

Configuração de entrada (`cisco_ios_l3_transit.txt`):
```cisco
hostname CISCO-TRANSITO
!
interface GigabitEthernet0/0.1234
 description CLIENTE-X-TRANSITO-IP
 encapsulation dot1Q 1234
 ip address 10.255.123.1 255.255.255.252
!
ip route 200.200.200.0 255.255.255.252 10.255.123.2
!
router bgp 65000
 bgp router-id 192.0.2.1
 neighbor 10.255.123.2 remote-as 64520
 neighbor 10.255.123.2 description CLIENTE-X
 !

## Gerência e Observabilidade (Huawei)

O sistema detecta configurações de gerência e observabilidade em equipamentos
Huawei/VRP: SNMP, NTP, Syslog, acesso administrativo (VTY/SSH) e usuários
locais.

### Funcionalidades

- **SNMP** — versões (v2c, v3), communities (mascaradas — nunca salvas),
  trap hosts, usuários SNMPv3, grupos, ACLs
- **NTP** — servidores, preferência, interface de origem, autenticação
- **Syslog/info-center** — loghosts, facilities
- **Acesso administrativo** — VTY, SSH/Stelnet, Telnet, ACLs nas linhas VTY
- **Usuários locais** — nome, privilégio, tipos de serviço (senha nunca salva)

### Segurança

> O sistema **nunca armazena** communities SNMP, senhas de usuários locais
> ou secrets de autenticação. Apenas flags e evidências mascaradas são
> preservadas (ex: `has_password: true`, `password_type: irreversible-cipher`).

### Serviços detectados

| Serviço | Tipo | Confiança |
|---------|------|-----------|
| SNMP | `snmp` | 0.80–0.85 |
| NTP | `ntp` | 0.60–0.85 |
| Syslog | `syslog` | 0.50–0.85 |
| Acesso Administrativo | `management_access` | 0.85–0.90 |
| Usuário Local | `local_user` | 0.70–0.90 |

### Issues/Riscos detectados

| Código | Severidade | Descrição |
|--------|-----------|-----------|
| `snmp_v2c_enabled` | Atenção | SNMP v2c habilitado |
| `snmp_write_community` | Crítico | Community de escrita detectada |
| `snmp_without_acl` | Crítico | SNMP sem ACL de restrição |
| `ntp_without_authentication` | Informativo | NTP sem autenticação |
| `syslog_without_loghost` | Atenção | Syslog sem servidor remoto |
| `telnet_enabled` | Crítico | Telnet habilitado |
| `vty_without_acl` | Atenção | VTY sem ACL de entrada |
| `local_user_high_privilege` | Atenção | Usuário com privilégio elevado |

### Exemplos CLI

```powershell
# Analisar configuração com SNMP/NTP/Syslog/VTY/SSH gerenciados
python manage.py analyze_config_file sample_configs/huawei_management_snmp_ntp_syslog.txt --vendor huawei --device-name "NE40-MGMT-TESTE"

# Analisar configuração com riscos de gerência
python manage.py analyze_config_file sample_configs/huawei_management_risky.txt --vendor huawei --device-name "NE40-MGMT-RISCO"

# Buscar serviços de gerência
python manage.py network_search "snmp"
python manage.py network_search "local-user admin"
python manage.py network_search "syslog"

# Comparar antes/depois de mudanças de gerência
python manage.py compare_config_files sample_configs/huawei_management_change_before.txt sample_configs/huawei_management_change_after.txt --vendor huawei --device-name "NE40-MGMT-DIFF"
```

### Arquivos de demonstração

| Arquivo | Descrição |
|---------|-----------|
| `huawei_management_snmp_ntp_syslog.txt` | Config de gerência completa (SNMP v2c/v3, NTP, syslog, VTY+SSH+ACL, local-users) |
| `huawei_management_risky.txt` | Config com riscos de gerência (Telnet, SNMP sem ACL, write community, etc.) |
| `huawei_management_change_before.txt` | Before para comparação de gerência |
| `huawei_management_change_after.txt` | After para comparação de gerência |

### Limitações atuais

- `acl` como bloco separado pode não ser parseado corretamente se iniciar
  com `acl number` — mas inline `acl 2001 inbound` dentro de VTY funciona.
- AAA blocks com sub-comandos têm parsing limitado (apenas `aaa` é capturado
  como bloco). `local-user` é extraído diretamente do texto bruto.
- A detecção de Telnet depende do VTY `protocol inbound` — Telnet via
  outras interfaces não é detectado.

## Como rodar (Windows / Desenvolvimento)

### 1. Clonar ou copiar o projeto

```bash
cd C:\Users\joao.silva\Documents\Nova pasta\netops_assistant
```

### 2. Criar ambiente virtual

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Instalar dependências

```bash
pip install -r requirements.txt
```

### 4. Configurar variáveis de ambiente

```bash
copy .env.example .env
# Edite .env se necessário (os defaults já funcionam para dev)
```

### 5. Rodar migrações

```bash
python manage.py migrate
```

### 6. Rodar testes

Testes do parser Huawei:
```bash
python manage.py test apps.parsers.huawei.tests
```

Testes do parser Cisco:
```bash
python manage.py test apps.parsers.cisco.tests
```

Testes de gerência e observabilidade:
```bash
python manage.py test apps.analysis.tests.test_management
```

Testes de switching L2 / VLAN / STP:
```bash
python manage.py test apps.analysis.tests.test_switching
```

Testes do fluxo de análise (inclui registry, circuitos, issues):
```bash
python manage.py test apps.analysis.tests
```

Todos os testes (644 atualmente):
```bash
python manage.py test
```

### Testes de integração de políticas

```bash
python manage.py test apps.analysis.tests.test_policy_integration
```

Testa o pipeline completo com `huawei_policy_full_visual.txt`:

* **Análise**: BGP, route-policy, ip-prefix, ACL, as-path-filter, community-filter, services
* **Documentação web**: seção "Políticas de Roteamento e Filtros", ACL rules em tabela, dependências BGP
* **Busca web**: EXPORT-CLIENTE, CLIENTE-X, 65000:100, as-path-filter
* **Comparação web**: IP Prefixes, Route-Policies, ACLs, AS-Path/Community Filters, validation/rollback

### Testes de políticas de roteamento e filtros

```bash
python manage.py test apps.analysis.tests.test_policy
```

### 7. Iniciar servidor

```bash
python manage.py runserver
```

Acesse: http://127.0.0.1:8000

### 8. Testar pelo navegador

1. Abra o arquivo `sample_configs/huawei_l3_transit_public_prefix.txt`
   no editor de texto
2. Copie todo o conteúdo
3. Acesse http://127.0.0.1:8000/configs/new/
4. Informe o nome do equipamento (ex: "ROTEADOR-TRANSITO-SP")
5. Cole a configuração no campo de texto
6. Clique em **Analisar Configuração**
7. Visualize os resultados com circuitos e issues detectados

## Migração para Linux (Produção)

1. Copie o projeto para o servidor Linux
2. Crie ambiente virtual: `python3 -m venv venv && source venv/bin/activate`
3. Instale dependências: `pip install -r requirements.txt`
4. Configure PostgreSQL no `.env` (vide `.env.example`)
5. Instale `psycopg2-binary`: `pip install psycopg2-binary`
6. Adicione ao `requirements.txt` se for usar PostgreSQL
7. Rode migrações: `python manage.py migrate`
8. Configure `DJANGO_DEBUG=False` e `DJANGO_ALLOWED_HOSTS=seu-dominio`
9. Use Gunicorn + Nginx para servir em produção

## Comandos básicos

```bash
# Testes
python manage.py test

# Shell Django
python manage.py shell

# Criar superusuário
python manage.py createsuperuser

# Coletar arquivos estáticos
python manage.py collectstatic
```

## Busca Técnica Global

O sistema possui uma **busca técnica global determinística** para localizar
rapidamente objetos dentro das configurações analisadas — sem usar IA.

A busca detecta automaticamente o tipo do termo consultado:

| Tipo detectado | Exemplo | O que procura |
|---------------|---------|---------------|
| VLAN | `1234`, `vlan 1234` | Interfaces, circuitos com VLAN |
| IP | `10.255.123.2` | Rotas, circuitos, peers BGP |
| Prefixo | `200.200.200.0/30` | Rotas, BGP networks, circuitos |
| Interface | `Eth-Trunk100.1234` | Interfaces, circuitos |
| ASN | `64520`, `AS64520` | Peers BGP, AS local |
| Texto | `RADIUS-ISP`, `CLIENTE-MEGA` | Descrições, serviços, VSI, texto bruto |

### Página web

Acesse **http://127.0.0.1:8000/search/** para uma interface de busca com
filtros por vendor, dispositivo e opção "apenas último snapshot".

### Busca via CLI

```bash
python manage.py network_search "vlan 1234"
python manage.py network_search "200.200.200.0/30"
python manage.py network_search "Eth-Trunk100.1234"
python manage.py network_search "RADIUS-ISP"
python manage.py network_search "VSI-CLIENTE-Z"
python manage.py network_search "CLIENTE-MEGA"

# Busca de políticas de roteamento e filtros
python manage.py network_search "EXPORT-CLIENTE"
python manage.py network_search "CLIENTE-X"
python manage.py network_search "as-path-filter 10"
python manage.py network_search "community-filter 20"
python manage.py network_search "65000:100"
python manage.py network_search "route-policy"
python manage.py network_search "ip-prefix"
```

Exemplo de saída:

```
=== BUSCA TÉCNICA GLOBAL ===
Query:        Eth-Trunk100.1234
Tipo:         interface

--- Resumo ---
  devices: 0
  snapshots: 0
  interfaces: 1
  circuits: 2
  services: 0
  issues: 0
  static_routes: 2
  bgp_peers: 0
  raw_matches: 1
  Total: 6

--- Interfaces (1) ---
  [0.9] Eth-Trunk100.1234
        Dispositivo: ROTEADOR-SEARCH-DEMO
        >> interface Eth-Trunk100.1234

--- Circuitos (2) ---
  [0.9] Trânsito L3 — Eth-Trunk100.1234
        Dispositivo: ROTEADOR-SEARCH-DEMO

--- Rotas Estáticas (2) ---
  [0.9] 200.200.200.0/30 → 10.255.123.2
        Dispositivo: ROTEADOR-SEARCH-DEMO
```

### Resultados

Cada resultado inclui:
- Tipo (dispositivo, interface, circuito, rota, BGP, policy/filtro, serviço, issue, raw)
- Título e descrição curta
- Dispositivo e snapshot de origem
- Score de relevância
- Evidência (trechos de configuração, sem expor a config inteira)

Os resultados são organizados por seção na página web e agrupados por tipo
no CLI.

### Busca global estruturada de policies

O sistema possui uma **busca estruturada de políticas e filtros** dentro de
`results["policies"]` no retorno de `global_network_search()`. A seção
`policies` aparece automaticamente na página `/search/` e no CLI quando
resultados são encontrados.

**Tipos de resultado na seção policies:**

| `result_type` | Descrição |
|---|---|
| `route_policy` | Route-policy cujo nome contém o termo buscado |
| `ip_prefix` | IP prefix-list ou regra individual cujo prefixo match |
| `acl` | ACL ou regra individual |
| `as_path_filter` | AS-path filter ou regra individual |
| `community_filter` | Community filter ou regra individual |
| `bgp_policy_dependency` | Peer BGP que referencia route-policy pelo nome |

**Exemplo de resultado:**

```python
{
    "type": "route_policy",
    "title": "Route-policy: EXPORT-CLIENTE",
    "description": "Node 10 (permit) | match: ip-prefix CLIENTE-X | apply: community 65000:100 additive",
    "device": "NE40-POLICY-FULL",
    "snapshot": 1,
    "parsed_config": 1,
    "url": "/analysis/1/",
    "score": 0.9,
    "metadata": {"policy_name": "EXPORT-CLIENTE", "node": 10},
    "evidence": ["route-policy EXPORT-CLIENTE permit node 10\\n if-match ip-prefix CLIENTE-X\\n apply community 65000:100 additive\\n"]
}
```

## Licença

Proprietário — Uso interno.
