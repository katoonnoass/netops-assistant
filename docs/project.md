# NetOps Assistant — Documentação Técnica

## Visão Geral

**NetOps Assistant** é uma plataforma Django para análise determinística de
configurações de equipamentos de rede. O sistema recebe a saída bruta de
comandos como `display current-configuration` (Huawei), parseia o conteúdo
em dados estruturados, detecta circuitos L3 e identifica problemas de
configuração — tudo sem IA, apenas com reconhecimento de padrões.

---

## Arquitetura do Projeto

```
netops_assistant/
│
├── manage.py                          # Entry point Django
├── requirements.txt                   # Dependências
├── .env.example                       # Template de variáveis de ambiente
│
├── netops_assistant/                  # Configuração do projeto Django
│   ├── __init__.py
│   ├── settings.py                    # Settings (SQLite dev, PostgreSQL prod)
│   ├── urls.py                        # Rotas (apenas /admin/)
│   └── wsgi.py
│
├── apps/
│   ├── __init__.py
│   │
│   ├── core/                          # Utilitários comuns (expansão futura)
│   │   ├── __init__.py
│   │   └── apps.py
│   │
│   ├── devices/                       # Cadastro de equipamentos
│   │   ├── __init__.py
│   │   ├── admin.py                   # DeviceAdmin
│   │   ├── apps.py
│   │   ├── models.py                  # Device
│   │   └── migrations/
│   │       └── 0001_initial.py
│   │
│   ├── config_archive/                # Snapshots de configuração
│   │   ├── __init__.py
│   │   ├── admin.py                   # ConfigSnapshotAdmin
│   │   ├── apps.py
│   │   ├── models.py                  # ConfigSnapshot
│   │   └── migrations/
│   │       └── 0001_initial.py
│   │
│   ├── parsers/                       # Parsers por fabricante
│   │   ├── __init__.py
│   │   ├── apps.py
│   │   ├── base.py                    # BaseParser (ABC)
│   │   ├── registry.py                # get_parser_for_vendor()
│   │   ├── tests.py                   # Re-export dos testes Huawei
│   │   │
│   │   └── huawei/
│   │       ├── __init__.py
│   │       ├── parser.py              # HuaweiVRPParser (478 linhas)
│   │       └── tests/
│   │           ├── __init__.py
│   │           ├── test_parser.py     # 26 testes
│   │           └── fixtures/
│   │               └── sample_config.txt
│   │
│   └── analysis/                      # Análise e detecção
│       ├── __init__.py
│       ├── admin.py                   # Admins com filtros e campos
│       ├── apps.py
│       ├── models.py                  # ParsedConfig, DetectedCircuit, AnalysisIssue
│       ├── services.py                # analyze_config_snapshot()
│       │
│       ├── detectors/
│       │   ├── __init__.py
│       │   ├── circuits.py            # detect_l3_transit_circuits()
│       │   └── issues.py              # detect_issues() (5 detectores)
│       │
│       ├── management/
│       │   ├── __init__.py
│       │   └── commands/
│       │       ├── __init__.py
│       │       ├── analyze_snapshot.py
│       │       └── analyze_config_file.py
│       │
│       ├── migrations/
│       │   ├── __init__.py
│       │   ├── 0001_initial.py
│       │   └── 0002_analysisissue_code_analysisissue_metadata_and_more.py
│       │
│       └── tests/
│           ├── __init__.py
│           ├── test_flow.py           # 30 testes de fluxo
│           └── fixtures/
│               ├── circuit_l3.txt
│               ├── missing_descriptions.txt
│               └── unreachable_next_hop.txt
│
└── docs/
    └── project.md                     # Este arquivo
```

---

## Modelos de Dados

### Device (`apps/devices/models.py`)

| Campo        | Tipo                    | Descrição                           |
|-------------|-------------------------|-------------------------------------|
| `name`      | `CharField(100, unique)`| Nome do equipamento                 |
| `vendor`    | `CharField(20, choices)`| Fabricante (huawei, zte, datacom, cisco, mikrotik, other) |
| `ip_address`| `GenericIPAddressField` | Endereço IP (opcional)              |
| `hostname`  | `CharField(255)`        | Hostname detectado                  |
| `description`| `TextField`            | Descrição livre                     |
| `created_at`| `DateTimeField`         | Auto criado em                      |
| `updated_at`| `DateTimeField`         | Auto atualizado em                  |

### ConfigSnapshot (`apps/config_archive/models.py`)

| Campo        | Tipo                    | Descrição                           |
|-------------|-------------------------|-------------------------------------|
| `device`    | `FK(Device, SET_NULL)`  | Equipamento associado (opcional)    |
| `raw_config`| `TextField`             | Configuração bruta (texto puro)     |
| `vendor`    | `CharField(20)`         | Fabricante (detectado ou informado) |
| `source`    | `CharField(20, choices)`| Origem: paste, upload, api          |
| `notes`     | `TextField`             | Observações                         |
| `created_at`| `DateTimeField`         | Auto criado em                      |

### ParsedConfig (`apps/analysis/models.py`)

| Campo           | Tipo                    | Descrição                          |
|-----------------|-------------------------|-------------------------------------|
| `snapshot`      | `FK(ConfigSnapshot, CASCADE)` | Snapshot de origem           |
| `parsed_data`   | `JSONField`             | Dados estruturados do parser        |
| `parser_version`| `CharField(20)`         | Versão do parser usado              |
| `created_at`    | `DateTimeField`         | Data da análise                     |

O campo `parsed_data` segue a estrutura retornada pelo parser:

```python
{
    "vendor": "huawei",
    "sysname": "RACK01-CORE-SW01",
    "blocks": [
        {"type": "interface", "header": "interface Eth-Trunk1.200", "raw": "...", "lines": [...]},
        {"type": "bgp", "header": "bgp 65000", "raw": "...", "lines": [...]},
        ...
    ],
    "interfaces": [
        {
            "name": "Eth-Trunk1.200",
            "type": "eth-trunk",
            "parent": "Eth-Trunk1",
            "subinterface_number": 200,
            "description": "TRANSPORTE-QINQ-CLIENTE-B",
            "ip_address": "10.200.0.1 255.255.255.252",
            "vlan_type": "dot1q",
            "vlan_id": "200",
            "shutdown": False,
            "raw": "interface Eth-Trunk1.200\n ..."
        },
        ...
    ],
    "bgp": [
        {
            "as_number": "65000",
            "peers": [
                {"ip": "10.200.0.2", "remote_as": "64500", "description": "BGP-CLIENTE-A"},
                ...
            ],
            "networks": ["10.0.0.0 mask 255.255.255.0", ...],
            "raw": "..."
        }
    ],
    "static_routes": [
        {
            "network": "200.200.200.0",
            "netmask": "255.255.255.252",
            "next_hop": "10.255.123.2",
            "preference": "60",
            "tag": "100",
            "description": "CLIENTE-X",
            "raw": "ip route-static 200.200.200.0 255.255.255.252 10.255.123.2"
        },
        ...
    ],
    "raw": "...",
    "block_count": 12
}
```

### DetectedCircuit (`apps/analysis/models.py`)

| Campo          | Tipo                       | Descrição                         |
|----------------|----------------------------|-----------------------------------|
| `snapshot`     | `FK(ConfigSnapshot, CASCADE)` | Snapshot de origem            |
| `circuit_type` | `CharField(30, choices)`   | Tipo: l3, l3_transit, vlan_transport, qinq, bgp, transport_mikrotik, olt, bng, l2vpn, other |
| `description`  | `TextField`                | Descrição do circuito             |
| `details`      | `JSONField`                | Detalhes específicos do tipo      |
| `created_at`   | `DateTimeField`            | Auto criado em                    |

Estrutura do `details` para circuitos `l3_transit`:

```python
{
    "interface": "Eth-Trunk100.1234",
    "vlan_id": 1234,
    "transit_network": "10.255.123.0/30",
    "local_ip": "10.255.123.1",
    "remote_ip": "10.255.123.2",
    "routed_prefix": "200.200.200.0/30",
    "confidence": 0.80,
    "vendor": "huawei",
    "evidence": {
        "interface": "Eth-Trunk100.1234",
        "vlan_id": 1234,
        "transit_network": "10.255.123.0/30",
        "local_ip": "10.255.123.1",
        "remote_ip": "10.255.123.2",
        "routed_prefix": "200.200.200.0/30",
        "static_route_raw": "ip route-static 200.200.200.0 255.255.255.252 10.255.123.2",
        "method": "dot1q_subinterface_with_connected_static_route"
    }
}
```

### AnalysisIssue (`apps/analysis/models.py`)

| Campo        | Tipo                       | Descrição                         |
|-------------|----------------------------|-----------------------------------|
| `snapshot`   | `FK(ConfigSnapshot, CASCADE)` | Snapshot de origem            |
| `severity`   | `CharField(10, choices)`   | info, warning, critical           |
| `category`   | `CharField(50)`            | Categoria livre                   |
| `code`       | `CharField(60)`            | Código único do tipo de issue     |
| `title`      | `CharField(200)`           | Título em português               |
| `description`| `TextField`                | Descrição detalhada               |
| `metadata`   | `JSONField`                | Evidências e dados contextuais    |
| `created_at` | `DateTimeField`            | Auto criado em                    |

---

## Parser Registry

**Arquivo:** `apps/parsers/registry.py`

O registry é o ponto central para descobrir parsers disponíveis:

```python
from apps.parsers.registry import get_parser_for_vendor, list_supported_vendors

# Resolve vendor para (canonical_name, parser_class)
canonical, ParserClass = get_parser_for_vendor("huawei")      # ("huawei", HuaweiVRPParser)
canonical, ParserClass = get_parser_for_vendor("huawei_vrp")  # ("huawei", HuaweiVRPParser)
canonical, ParserClass = get_parser_for_vendor("vrp")         # ("huawei", HuaweiVRPParser)

# Lista vendors suportados
vendors = list_supported_vendors()  # ["huawei"]

# Vendor não suportado → KeyError
get_parser_for_vendor("cisco")  # KeyError: "Parser para vendor 'cisco' não encontrado..."
```

### Como adicionar um novo parser

1. Crie uma pasta `apps/parsers/<fabricante>/`
2. Implemente uma classe que herde de `apps.parsers.base.BaseParser`
3. Defina o atributo `vendor` e implemente o método `parse()`
4. No `apps/parsers/registry.py`, adicione ao `PARSER_REGISTRY`:

```python
from apps.parsers.cisco import CiscoIOSParser

PARSER_REGISTRY["cisco"] = ("cisco", CiscoIOSParser)
PARSER_REGISTRY["cisco_ios"] = ("cisco", CiscoIOSParser)
```

---

## Serviço de Análise

**Arquivo:** `apps/analysis/services.py`

Função principal:

```python
def analyze_config_snapshot(snapshot: ConfigSnapshot) -> ParsedConfig
```

### Fluxo interno

```
analyze_config_snapshot(snapshot)
│
├─ 1. Valida raw_config não vazio
│
├─ 2. Detecta vendor se vazio (snapshot.vendor = "huawei" se achar "sysname")
│
├─ 3. get_parser_for_vendor(vendor) → (canonical, ParserClass)
│
├─ 4. parser = ParserClass(snapshot.raw_config)
│     parsed_data = parser.parse()
│
├─ 5. Deleta ParsedConfig antigo (se houver reanálise)
│     ParsedConfig.objects.filter(snapshot=snapshot).delete()
│
├─ 6. parsed_config = ParsedConfig.objects.create(snapshot=snapshot, parsed_data=parsed_data)
│
├─ 7. Deleta DetectedCircuit e AnalysisIssue antigos
│     DetectedCircuit.objects.filter(snapshot=snapshot).delete()
│     AnalysisIssue.objects.filter(snapshot=snapshot).delete()
│
├─ 8. detect_l3_transit_circuits(snapshot, parsed_data)
│
├─ 9. detect_issues(snapshot, parsed_data)
│
└─ 10. Retorna parsed_config
```

O fluxo é **idempotente**: rodar N vezes produz o mesmo resultado no banco
(sem duplicatas).

---

## Detectores

### Detector de Circuitos L3 Transit

**Arquivo:** `apps/analysis/detectors/circuits.py`

**Algoritmo:**

1. Para cada interface com `vlan_type == "dot1q"` e IP /30:
   - Calcula a rede de trânsito (ex: `10.255.123.0/30`)
   - Extrai o IP local da interface (ex: `10.255.123.1`)
2. Para cada rota estática, verifica se o next-hop está dentro da rede /30:
   - Se sim, é um circuito candidate
   - Se o destino da rota é diferente do /30 de trânsito, esse destino é o `routed_prefix`
3. Cria `DetectedCircuit(circuit_type="l3_transit", confidence=0.80)`

**Exemplo de match:**

```
interface Eth-Trunk100.1234        → vlan_type=dot1q, ip=10.255.123.1/30
ip route-static 200.200.200.0/30 10.255.123.2   → nh=10.255.123.2 ∈ 10.255.123.0/30 ✓
```

Resultado: circuito detectado com transit_network=`10.255.123.0/30`,
routed_prefix=`200.200.200.0/30`.

### Detectores de Issues

**Arquivo:** `apps/analysis/detectors/issues.py`

| Código | Severidade | Lógica |
|--------|-----------|--------|
| `interface_missing_description` | info | Interface física ou Eth-Trunk sem `description` |
| `subinterface_missing_description` | warning | Subinterface dot1q sem `description` |
| `static_route_missing_description` | warning | Rota estática (não-default) sem `description` |
| `bgp_peer_missing_description` | warning | Peer BGP sem `description` |
| `static_route_unreachable_next_hop` | critical | Next-hop da rota não pertence a nenhuma rede conectada |

---

## Comandos de Gerenciamento

### `analyze_snapshot`

```bash
python manage.py analyze_snapshot <snapshot_id>
```

Analisa um `ConfigSnapshot` existente pelo ID. Cria/atualiza `ParsedConfig`,
`DetectedCircuit` e `AnalysisIssue`. Imprime resumo com contagens e lista
de issues e circuitos encontrados.

### `analyze_config_file`

```bash
python manage.py analyze_config_file <caminho_do_arquivo> \
    --vendor huawei \
    --device-name "MEU-ROTEADOR"
```

Fluxo completo:
1. Lê o arquivo de configuração
2. Cria (ou reusa) `Device` com o nome informado
3. Cria `ConfigSnapshot` com o conteúdo
4. Executa `analyze_config_snapshot()`
5. Imprime resumo completo

---

## Testes

### Huawei Parser (26 testes)

```bash
python manage.py test apps.parsers.huawei.tests
```

Cobre: extração de sysname, blocos, interfaces (física, Eth-Trunk, subinterface dot1q,
LoopBack, VLANIF), BGP (AS, peers, networks), rotas estáticas (preference, tag),
configuração vazia.

### Fluxo de Análise (30 testes)

```bash
python manage.py test apps.analysis.tests
```

Cobre:

- Registry: resolução por nome canônico, alias, case-insensitive, vendor inválido
- Service: criação de ParsedConfig, detecção de interfaces/rotas, circuitos, issues, erro sem vendor, erro config vazia
- Idempotência: reanálise não duplica registros
- L3 Circuit: campos corretos (interface, vlan_id, transit_network, local_ip, remote_ip, routed_prefix, confidence), não-detecção de interfaces sem rota correspondente
- Issues: interface sem descrição, subinterface sem descrição, rota sem descrição, BGP peer sem descrição, next-hop inalcançável
- Unreachable: detecção de next-hop sem rede conectada, não-detecção de next-hop com rede conectada

### Todos os testes

```bash
python manage.py test
```

**Total: 56 testes**

---

## Exemplos Completos

### Exemplo 1: Circuito L3 com prefixo público roteado

Configuração (`circuito.txt`):
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

Comando:
```bash
python manage.py analyze_config_file circuito.txt --vendor huawei --device-name "ROTEADOR"
```

Saída:
```
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

### Exemplo 2: Configuração completa com issues

Usando a fixture do parser:
```bash
python manage.py analyze_config_file apps/parsers/huawei/tests/fixtures/sample_config.txt \
    --vendor huawei --device-name "NE40-TESTE"
```

Saída:
```
=== RESUMO DA ANÁLISE ===
  ParsedConfig #:           2
  Interfaces detectadas:    7
  Rotas estáticas:          3
  Circuitos detectados:     1
  Issues encontradas:       2

--- Issues ---
  [Atenção/static_route_missing_description] Rota estática sem descrição: 10.0.0.0/255.0.0.0
  [Atenção/static_route_missing_description] Rota estática sem descrição: 172.16.0.0/255.255.0.0

--- Circuitos ---
  [Trânsito L3] Eth-Trunk1.200 (local: 10.200.0.1 -> remote: 10.200.0.2)
    Prefixo roteado: 0.0.0.0/0
```

### Exemplo 3: Circuito L3 com múltiplas issues

```bash
python manage.py analyze_config_file apps/analysis/tests/fixtures/circuit_l3.txt \
    --vendor huawei --device-name "ROTEADOR-TRANSITO"
```

Saída:
```
=== RESUMO DA ANÁLISE ===
  ParsedConfig #:           3
  Interfaces detectadas:    8
  Rotas estáticas:          4
  Circuitos detectados:     1
  Issues encontradas:       5

--- Issues ---
  [Atenção/static_route_missing_description] Rota estática sem descrição: 10.0.0.0/255.0.0.0
  [Atenção/static_route_missing_description] Rota estática sem descrição: 172.16.0.0/255.255.0.0
  [Atenção/static_route_missing_description] Rota estática sem descrição: 200.200.200.0/255.255.255.252
  [Informativo/interface_missing_description] Interface sem descrição: GigabitEthernet0/0/2
  [Crítico/static_route_unreachable_next_hop] Next-hop inalcançável: 192.168.255.1

--- Circuitos ---
  [Trânsito L3] Eth-Trunk100.1234 (local: 10.255.123.1 -> remote: 10.255.123.2)
    Prefixo roteado: 200.200.200.0/30
```

---

## Pipeline de Dados

```
                    ┌──────────────┐
                    │  raw_config  │  Texto bruto (display current-configuration)
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    Parser    │  HuaweiVRPParser.parse()
                    │              │  → blocos, interfaces, BGP, rotas
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ parsed_data  │  JSON estruturado (dict aninhado)
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
       ┌──────────┐ ┌──────────┐ ┌──────────┐
       │Circuitos │ │  Issues  │ │  (futuro) │
       │ L3, ...  │ │ 5 tipos  │ │ doc,etc  │
       └──────────┘ └──────────┘ └──────────┘
              │            │
              ▼            ▼
       ┌──────────┐ ┌──────────┐
       │  Banco   │ │  Banco   │
       │Detected  │ │Analysis  │
       │Circuit   │ │Issue     │
       └──────────┘ └──────────┘
```

---

## Administração Django

Todos os modelos estão registrados no admin em `/admin/`:

| Modelo | list_display | list_filter |
|--------|-------------|-------------|
| Device | name, vendor, ip_address, hostname, created_at | vendor |
| ConfigSnapshot | __str__, device, vendor, source, created_at | vendor, source, created_at |
| ParsedConfig | __str__, snapshot, vendor_info, interface_count, parser_version, created_at | parser_version, created_at |
| DetectedCircuit | __str__, circuit_type, circuit_interface, circuit_transit, snapshot, created_at | circuit_type, created_at |
| AnalysisIssue | __str__, severity, code, title, snapshot, created_at | severity, code, created_at |

---

## Limitações Atuais

1. **Apenas Huawei/VRP**: outros fabricantes (ZTE, Datacom, Cisco, MikroTik)
   não têm parser implementado

2. **Apenas circuito L3 transit**: detectores para vlan_transport, qinq, bgp,
   olt, bng, l2vpn não foram implementados

3. **Apenas 5 tipos de issue**: cobertura básica; não valida BGP completo,
   ACLs, OSPF, políticas de roteamento, etc.

4. **Confidence fixo (0.80)**: o detector L3 atribui confidence fixo;
   idealmente seria calculado com base em múltiplas evidências

5. **Sem auto-detecção de vendor no admin**: o campo `vendor` do
   `ConfigSnapshot` precisa ser preenchido manualmente ao criar pelo admin

6. **Sem API REST**: apenas admin Django disponível; DRF está instalado
   mas sem endpoints

7. **Sem frontend**: sem templates, formulários ou interface web além do admin

8. **Default route como routed_prefix**: quando a rota de match é uma default
   (0.0.0.0/0), ela aparece como prefixo roteado — conceitualmente correto
   mas pode confundir

---

## Guia de Desenvolvimento

### Adicionar um novo detector de circuito

1. Crie a função em `apps/analysis/detectors/circuits.py`
2. A função deve receber `(snapshot, parsed_data)` e retornar `list[DetectedCircuit]`
3. Os objetos devem ser salvos (`circuit.save()`) dentro da função
4. Importe e chame a função em `apps/analysis/services.py` dentro de `analyze_config_snapshot()`

### Adicionar um novo detector de issue

1. Crie a função em `apps/analysis/detectors/issues.py`
2. A função deve receber `(snapshot, parsed_data)` e retornar `list[AnalysisIssue]`
3. Use o helper `_make_issue()` para criar e salvar issues consistentemente
4. Importe e chame a função em `detect_issues()` (já integrada ao service)

### Adicionar um novo parser de fabricante

1. Crie `apps/parsers/<fabricante>/parser.py` com classe herdando de `BaseParser`
2. Implemente `parse()` retornando dict com chaves `vendor`, `blocks`, `interfaces`, `static_routes`, `raw`
3. Registre em `apps/parsers/registry.py` no `PARSER_REGISTRY`
4. Crie testes em `apps/parsers/<fabricante>/tests/`
