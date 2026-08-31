"""Protocolo local da ANM 24 Net G2 (código de modelo ``0x25``).

A G2 estava mapeada na família 2018, que fala ISECMobile V1 com o comando
``0x5A``. No acesso **local pela porta 9009 ela não responde a isso** — nem com
erro: dez frames V1 bem formados, com senhas de 4 e de 6 dígitos, foram
ignorados em silêncio absoluto. A central fala o enquadramento **V2**, o mesmo
da família AMT 8000, mas com um conjunto de comandos próprio.

Tudo aqui foi confirmado por captura do tráfego do app oficial AMT Remoto
Mobile e depois reproduzido contra o hardware (ANM 24 NET - G2, firmware
1.0.3, 31/08/2026). Onde algo **não** foi verificado, o comentário diz.

Sequência de uma sessão::

    05 e7 01 10 06 60 6a          prelúdio (o AMT 8000 não usa)
    0xF0F0 + senha                autenticação — só exigida para escrita
    ... comandos ...
    0xF0F1                        encerramento

Enquadramento (idêntico ao da AMT 8000)::

    [destino 2B] [origem 2B] [tamanho 2B] [comando 2B] [conteúdo] [checksum]

``tamanho`` conta comando + conteúdo; ``checksum`` é o XOR de tudo que vem
antes, complementado (``^ 0xFF``). Na resposta, origem e destino trocam.

Duas armadilhas descobertas no hardware, ambas capazes de gerar defeito
intermitente em produção:

* **Uma sessão local por vez, com carência.** Reconectar logo após fechar dá
  timeout, mesmo mandando ``0xF0F1`` e recebendo o ACK. Por isso o cliente
  precisa manter **uma conexão aberta**, não abrir e fechar a cada consulta.
* **A central entrega respostas atrasadas.** Uma consulta que expirou pode ser
  respondida na conexão *seguinte*. Sem descartar o que estiver pendente ao
  conectar, o status exibido é o da pergunta anterior.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Prelúdio fixo que abre a sessão. Conteúdo capturado do app; o significado
# dos bytes internos não foi decifrado, mas a central só passa a responder
# comandos V2 depois de recebê-lo.
ANM24_PRELUDE = bytes([0x05, 0xE7, 0x01, 0x10, 0x06, 0x60, 0x6A])
ANM24_PRELUDE_REPLY_PREFIX = bytes([0x05, 0xE7])

ANM24_SRC_ID = (0x00, 0xF1)

CMD_AUTH = (0xF0, 0xF0)
CMD_DISCONNECT = (0xF0, 0xF1)
CMD_MODEL = (0x00, 0x60)
CMD_STATUS = (0x0B, 0x01)
CMD_ARM_DISARM = (0x40, 0x1E)
CMD_ZONE_CONFIG = (0x33, 0xA0)
CMD_ZONE_NAMES = (0x33, 0xE0)
CMD_MAC = (0x3F, 0xAA)
CMD_READ_BEEP = (0x35, 0x1A)
CMD_WRITE_BEEP = (0x25, 0x1A)

ACK = (0xF0, 0xFE)
NACK = (0xF0, 0xFD)

ALL_PARTITIONS = 0xFF
MODE_DISARM = 0x00
MODE_ARM_AWAY = 0x01
MODE_ARM_STAY = 0x02
MODE_FORCE_ARM = 0x03

# Estado no primeiro byte do conteúdo de 0x0B01. Medido nas duas direções,
# quatro transições: 0x64 armada, 0x04 desarmada. O bit 2 (0x04) fica ligado
# nos dois casos; a diferença está em 0x60.
STATE_ARMED_MASK = 0x60

ZONE_COUNT = 24
ZONE_NAME_LEN = 14

# Bipe de arme/desarme: bit 2 do segundo byte lido por 0x351A. Confirmado com
# quatro gravações feitas pelo app (duas ligando, duas desligando) e conferido
# contra a tela do AMT Remoto, que mostrava "Off" com o valor 0x00.
BEEP_MASK = 0x04


class Anm24ProtocolError(Exception):
    """Frame malformado, checksum inválido ou resposta inesperada."""


def checksum(data: bytes) -> int:
    """XOR de todos os bytes, complementado."""
    x = 0
    for b in data:
        x ^= b
    return (x ^ 0xFF) & 0xFF


def build_frame(opcode: tuple[int, int], content: bytes = b"") -> bytes:
    """Monta um frame V2 pronto para envio."""
    src0, src1 = ANM24_SRC_ID
    body = bytes(opcode) + content
    if len(body) > 0xFFFF:
        raise ValueError("Conteúdo excede o tamanho máximo do frame")
    frame = bytes([0x00, 0x00, src0, src1, len(body) >> 8, len(body) & 0xFF]) + body
    return frame + bytes([checksum(frame)])


@dataclass
class ParsedFrame:
    """Resultado da leitura de um frame de resposta."""

    opcode: tuple[int, int]
    content: bytes
    valid_checksum: bool
    raw: bytes = field(repr=False)

    @property
    def is_nack(self) -> bool:
        return self.opcode == NACK

    @property
    def is_ack(self) -> bool:
        return self.opcode == ACK


def parse_frame(raw: bytes) -> ParsedFrame:
    """Interpreta um frame recebido da central."""
    if len(raw) < 9:
        raise Anm24ProtocolError(f"Frame curto demais: {len(raw)} bytes")
    length = (raw[4] << 8) | raw[5]
    fim = 6 + length
    if fim + 1 > len(raw):
        raise Anm24ProtocolError(
            f"Frame truncado: cabeçalho anuncia {length} bytes de corpo, chegaram {len(raw) - 7}"
        )
    return ParsedFrame(
        opcode=(raw[6], raw[7]),
        content=raw[8:fim],
        valid_checksum=checksum(raw[:fim]) == raw[fim],
        raw=raw,
    )


def cmd_auth(password: str) -> bytes:
    """Monta a autenticação ``0xF0F0``.

    Conteúdo = ``0x01`` + os dígitos da senha, um por byte + preenchimento
    ``0x00`` até seis posições + ``0x10 0x00``.

    **Não** é o mesmo layout da AMT 8000, apesar do comando ter o mesmo
    número: lá o prefixo é ``0x03``, o preenchimento é ``0x01`` e o final é
    ``0x01 0x00``. Reaproveitar aquela função aqui produz um frame que a
    central recusa.

    Uma incógnita: a senha capturada não tem o dígito zero, então não dá para
    saber se ele viaja como ``0x00`` ou como ``0x0A`` — a AMT 8000 usa
    ``0x0A``. Com senha contendo zero, este código pode falhar.
    """
    if not password.isdigit() or not (1 <= len(password) <= 6):
        raise ValueError("A senha deve ter de 1 a 6 dígitos numéricos")
    digitos = [int(d) for d in password]
    digitos += [0x00] * (6 - len(digitos))
    return build_frame(CMD_AUTH, bytes([0x01]) + bytes(digitos) + bytes([0x10, 0x00]))


def cmd_disconnect() -> bytes:
    """Encerramento limpo. A central responde ACK, mas ainda assim precisa de
    alguns segundos antes de aceitar outra sessão local."""
    return build_frame(CMD_DISCONNECT)


def cmd_model() -> bytes:
    return build_frame(CMD_MODEL)


def cmd_status() -> bytes:
    """Status ``0x0B01``.

    O ``0x0B4A`` da AMT 8000 **não** serve: o app oficial o tentou 51 vezes
    nesta central e levou NACK nas 51.
    """
    return build_frame(CMD_STATUS)


def cmd_arm_disarm(partition: int = ALL_PARTITIONS, mode: int = MODE_ARM_AWAY) -> bytes:
    """Arma ou desarma. Conteúdo ``[partição, modo]``.

    Armar (``0x01``) e desarmar (``0x00``) com ``partição=0xFF`` foram
    executados no hardware e confirmados pela leitura do status logo em
    seguida. Parcial (``0x02``) e forçado (``0x03``) vêm da tabela de
    operações e **não** foram testados nesta central.
    """
    return build_frame(CMD_ARM_DISARM, bytes([partition & 0xFF, mode & 0xFF]))


def cmd_zone_config() -> bytes:
    """Mapa de zonas configuradas: 2 bytes por zona, ``01 00`` = em uso."""
    return build_frame(CMD_ZONE_CONFIG, bytes([0xFF]))


def cmd_zone_names(indices: list[int]) -> bytes:
    """Nomes das zonas. Aceita uma lista de índices (base 0) e devolve 15
    bytes de texto para cada um."""
    return build_frame(CMD_ZONE_NAMES, bytes(i & 0xFF for i in indices))


def cmd_mac() -> bytes:
    return build_frame(CMD_MAC, bytes([0x00]))


def cmd_read_beep() -> bytes:
    """Lê o bipe de arme/desarme (``0x351A``)."""
    return build_frame(CMD_READ_BEEP, bytes([0x00]))


def cmd_write_beep(enabled: bool) -> bytes:
    """Grava o bipe de arme/desarme (``0x251A``).

    Os dois valores gravados pelo app foram ``00 04`` (ligado) e ``00 00``
    (desligado) — é esse par que se replica aqui, em vez de calcular o byte,
    para não mexer sem querer em outros bits do mesmo endereço.
    """
    return build_frame(CMD_WRITE_BEEP, bytes([0x00, BEEP_MASK if enabled else 0x00]))


@dataclass
class Anm24Status:
    """Status decodificado de ``0x0B01``."""

    activated: bool
    state_byte: int
    panel_datetime_str: str | None


def _bcd(value: int) -> int:
    return (value >> 4) * 10 + (value & 0x0F)


def parse_status(content: bytes) -> Anm24Status:
    """Interpreta o conteúdo de ``0x0B01`` (50 bytes).

    Layout confirmado: primeiro byte com o estado, 43 bytes que se mantiveram
    zerados em todas as leituras, e seis bytes finais de data/hora em BCD
    (``dd mm aa hh mm ss``). O relógio serve de prova de alinhamento — se ele
    bater com a hora real, os offsets estão certos.

    Os 43 bytes do meio **não** foram decifrados: todas as capturas foram
    feitas com as 24 zonas fechadas, então não há como saber quais deles
    carregam o estado das zonas. É por isso que esta família ainda não expõe
    sensores de zona.
    """
    if len(content) < 7:
        raise Anm24ProtocolError(f"Status curto demais: {len(content)} bytes")

    state_byte = content[0]
    relogio = content[-6:]
    try:
        dia, mes, ano, hora, minuto, seg = (_bcd(b) for b in relogio)
        panel_dt = f"{dia:02d}/{mes:02d}/20{ano:02d} {hora:02d}:{minuto:02d}:{seg:02d}"
    except (ValueError, IndexError):
        panel_dt = None

    return Anm24Status(
        activated=bool(state_byte & STATE_ARMED_MASK),
        state_byte=state_byte,
        panel_datetime_str=panel_dt,
    )


def parse_model(content: bytes) -> tuple[int, str]:
    """Devolve ``(código do modelo, firmware)`` de ``0x0060``.

    ``25 01 00 03 …`` → modelo ``0x25``, firmware ``1.0.3`` — o mesmo que o
    AMT Remoto mostra na tela da central.
    """
    if len(content) < 4:
        raise Anm24ProtocolError("Resposta de modelo curta demais")
    return content[0], f"{content[1]}.{content[2]}.{content[3]}"


def parse_zone_config(content: bytes) -> dict[int, bool]:
    """Zonas em uso, a partir de ``0x33A0``. Pula o byte de índice inicial."""
    pares = content[1:]
    return {
        i + 1: pares[i * 2 : i * 2 + 2] != b"\x00\x00"
        for i in range(min(ZONE_COUNT, len(pares) // 2))
    }


def parse_zone_names(content: bytes) -> dict[int, str]:
    """Nomes das zonas de ``0x33E0``: registros de índice + 15 bytes de texto."""
    nomes: dict[int, str] = {}
    passo = ZONE_NAME_LEN + 1  # 1 byte de indice + o texto
    for off in range(0, len(content) - ZONE_NAME_LEN, passo):
        idx = content[off]
        texto = content[off + 1 : off + passo].split(b"\x00")[0].decode("latin-1").strip()
        if texto:
            nomes[idx + 1] = texto
    return nomes


def parse_beep(content: bytes) -> bool:
    """Lê o bipe de ``0x351A``. Conteúdo ``00 04`` = ligado, ``00 00`` = desligado."""
    if len(content) < 2:
        raise Anm24ProtocolError("Resposta de configuração curta demais")
    return bool(content[1] & BEEP_MASK)


def build_panel_status(
    status: Anm24Status,
    model_key: str,
    model_name: str,
    family: str,
    firmware: str,
) -> "PanelStatus":  # noqa: F821 - importado só em tempo de execução
    """Converte a leitura de ``0x0B01`` na dataclass família-agnóstica do projeto.

    A maior parte dos campos fica vazia porque **esta central não os informa
    neste comando**, não porque foram esquecidos. O status da G2 traz 50 bytes:
    um de estado, 43 que se mantiveram zerados em todas as capturas e seis de
    relógio. Falta de rede elétrica, bateria, sirene, tamper, problemas de
    teclado e receptor não aparecem ali — e preencher com ``False`` seria
    afirmar que estão bem, o que é diferente de não saber.

    ``zones_open`` fica vazio pelo mesmo motivo: todas as capturas foram feitas
    com as 24 zonas fechadas, então não há como saber onde mora esse estado.
    Enquanto isso não for medido com uma zona aberta, esta família não expõe
    sensores de zona — melhor não ter a entidade do que ter uma que mente.
    """
    from .protocol import PanelStatus

    vazio: dict[int, bool] = {}

    return PanelStatus(
        model_key=model_key,
        model_name=model_name,
        family=family,
        firmware=firmware,
        zones_open=vazio,
        zones_violated=vazio,
        zones_bypassed=vazio,
        zones_low_battery=vazio,
        partition_mode_enabled=False,
        partitions_armed={"CENTRAL": status.activated},
        activated=status.activated,
        zone_triggered=False,
        trigger_bit_latched=False,
        zone_open_flag=False,
        status_byte_raw=status.state_byte,
        status_byte_name="status0b01",
        partition_status_bytes={"status0b01": status.state_byte},
        partition_bit_map={},
        siren_on=False,
        problem=False,
        ac_power_fault=False,
        battery_low=False,
        battery_missing_or_reversed=False,
        battery_short=False,
        aux_overload=False,
        battery_level=0,
        pgm_state=vazio,
        panel_datetime_str=status.panel_datetime_str,
        siren_wire_cut=False,
        siren_short_circuit=False,
        phone_line_cut=False,
        event_communication_failure=False,
        keypad_problem=vazio,
        receiver_problem=vazio,
        keypad_tamper=vazio,
        zones_tamper=vazio,
        zones_short_circuit=vazio,
        pgm_expander_problem=vazio,
        zone_expander_problem=vazio,
        zones_comm_failure=vazio,
    )
