"""Cliente TCP assíncrono e persistente para a ANM 24 Net G2 (local, porta 9009).

Espelha ``panel_client_amt8000.py`` — conexão aberta uma vez e mantida, comandos
serializados por um lock — com três diferenças exigidas por esta central:

1. **Prelúdio.** Antes de qualquer coisa vai ``05 e7 01 10 06 60 6a``, num
   enquadramento antigo (``[tamanho][corpo][checksum]``, tamanho na posição 0).
   Sem ele a central aceita a conexão TCP e ignora todo comando V2, sem sequer
   devolver erro.

2. **Descarte do que ficou pendente.** Uma consulta que expirou pode ser
   respondida na conexão *seguinte*. Sem drenar o que já estiver no buffer ao
   conectar, cada resposta fica deslocada em uma posição e o status exibido é o
   da pergunta anterior — defeito que se manifesta só de vez em quando, e por
   isso é caro de diagnosticar depois.

3. **Encerramento e carência.** ``0xF0F1`` fecha a sessão e a central confirma
   com ACK, mas ela ainda leva alguns segundos para aceitar outra sessão local.
   Reabrir a conexão a cada consulta funcionaria nos testes e falharia em uso
   real; por isso a conexão é mantida.
"""
from __future__ import annotations

import asyncio
import logging

from .const import DEFAULT_REQUEST_TIMEOUT
from .protocol_anm24 import (
    ANM24_PRELUDE,
    NACK,
    Anm24ProtocolError,
    ParsedFrame,
    cmd_auth,
    cmd_disconnect,
    parse_frame,
)

_LOGGER = logging.getLogger(__name__)

# Tempo dado à central para despejar respostas atrasadas ao conectar. Curto de
# propósito: é lixo do passado, não vale segurar a partida por causa dele.
_DRAIN_TIMEOUT = 0.4

# A central atende uma sessao local por vez e leva alguns segundos para
# liberar depois que a anterior fecha - mesmo com o 0xF0F1 enviado e o ACK
# recebido. Nesse intervalo ela ACEITA o TCP e nao responde ao preludio, o que
# de fora e indistinguivel de central fora do ar.
#
# Isso nao e teorico: a deteccao do modelo abre uma sessao e fecha, e o
# primeiro poll do coordinator vem logo atras - direto na carencia. Sem
# repetir, a integracao nasce falhando na propria configuracao.
_CONNECT_RETRIES = 3
_CONNECT_RETRY_DELAY = 5.0


class Anm24ConnectionError(Exception):
    """Falha ao conectar, autenticar ou comunicar com a ANM 24 Net G2."""


class Anm24AuthError(Anm24ConnectionError):
    """A central recusou a senha."""


class PanelClientAnm24:
    """Mantém uma conexão TCP persistente com a ANM 24 Net G2.

    A senha só entra quando alguém manda alterar algo: leitura de status,
    modelo, zonas e configuração funciona sem autenticar.
    """

    def __init__(
        self,
        host: str,
        port: int,
        password: str,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
        enabled: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._password = password
        self._timeout = timeout
        self._enabled = enabled
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._authenticated = False
        self._lock = asyncio.Lock()

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        if not enabled:
            await self.disconnect()

    async def connect(self) -> None:
        async with self._lock:
            if not self._connected:
                await self._connect_locked()

    async def disconnect(self) -> None:
        async with self._lock:
            await self._close_locked()

    async def _close_locked(self) -> None:
        """Encerra a sessão avisando a central antes de derrubar o socket."""
        if self._writer is not None and self._connected:
            try:
                self._writer.write(cmd_disconnect())
                await asyncio.wait_for(self._writer.drain(), timeout=2)
            except (OSError, asyncio.TimeoutError):
                pass  # a central já pode ter ido embora; o socket cai a seguir
        self._connected = False
        self._authenticated = False
        if self._writer is not None:
            try:
                self._writer.close()
                await asyncio.wait_for(self._writer.wait_closed(), timeout=3)
            except (OSError, asyncio.TimeoutError):
                pass
        self._reader = None
        self._writer = None

    async def _connect_locked(self) -> None:
        """Abre a sessao, repetindo enquanto a central estiver em carencia."""
        ultima: Exception | None = None
        for tentativa in range(1, _CONNECT_RETRIES + 1):
            try:
                await self._abrir_sessao_locked()
                return
            except Anm24ConnectionError as err:
                ultima = err
                if tentativa < _CONNECT_RETRIES:
                    _LOGGER.debug(
                        "ANM 24 G2: tentativa %d de %d falhou (%s); a central pode estar "
                        "em carencia entre sessoes, tentando de novo em %.0fs",
                        tentativa, _CONNECT_RETRIES, err, _CONNECT_RETRY_DELAY,
                    )
                    await asyncio.sleep(_CONNECT_RETRY_DELAY)
        assert ultima is not None
        raise ultima

    async def _abrir_sessao_locked(self) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), timeout=self._timeout
            )
            self._connected = True
            _LOGGER.debug("ANM 24 G2: conectado em %s:%s", self._host, self._port)
        except (OSError, asyncio.TimeoutError) as err:
            self._connected = False
            raise Anm24ConnectionError(
                f"Não foi possível conectar a {self._host}:{self._port}: {err}"
            ) from err

        await self._drain_stale_locked()
        await self._handshake_locked()

    async def _ensure_authenticated_locked(self) -> None:
        """Autentica sob demanda, na primeira escrita da sessão.

        Ler status, modelo, zonas e configuração **não** exige senha nesta
        central — só o prelúdio. Autenticar ao conectar faria a integração
        inteira falhar com senha errada, inclusive a leitura, que funcionaria
        perfeitamente; e o erro apareceria como "não conectou", longe da causa.
        Adiando para a primeira escrita, o status continua vivo e a senha
        errada reclama onde importa: no comando de armar ou desarmar.
        """
        if self._authenticated:
            return
        auth = await self._send_v2_locked(cmd_auth(self._password), context="autenticação")
        if auth.opcode == NACK:
            raise Anm24AuthError("Senha recusada pela central")
        self._authenticated = True
        _LOGGER.debug("ANM 24 G2: sessão autenticada")

    async def _drain_stale_locked(self) -> None:
        """Descarta respostas de sessões anteriores que a central ainda deva."""
        assert self._reader is not None
        while True:
            try:
                sobra = await asyncio.wait_for(
                    self._reader.read(4096), timeout=_DRAIN_TIMEOUT
                )
            except asyncio.TimeoutError:
                return
            if not sobra:
                return
            _LOGGER.debug(
                "ANM 24 G2: descartando %d bytes de resposta atrasada: %s",
                len(sobra),
                sobra.hex(" ").upper(),
            )

    async def _handshake_locked(self) -> None:
        """Envia o prelúdio e consome a resposta, que não usa o formato V2."""
        assert self._reader is not None and self._writer is not None
        try:
            self._writer.write(ANM24_PRELUDE)
            await self._writer.drain()
            tamanho = await asyncio.wait_for(self._reader.readexactly(1), timeout=self._timeout)
            await asyncio.wait_for(
                self._reader.readexactly(tamanho[0] + 1), timeout=self._timeout
            )
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as err:
            await self._close_locked()
            raise Anm24ConnectionError(
                f"A central não respondeu ao prelúdio de abertura: {err}"
            ) from err

    async def send_command(
        self, frame: bytes, context: str | None = None, requires_auth: bool = False
    ) -> ParsedFrame:
        """Envia um frame pronto e devolve a resposta, reconectando se preciso.

        requires_auth só para comandos que **alteram** algo: a senha é
        enviada uma vez por sessão, na primeira escrita.
        """
        if not self._enabled:
            raise Anm24ConnectionError("Comunicação com a central está desativada")

        async with self._lock:
            if not self._connected:
                await self._connect_locked()
            if requires_auth:
                await self._ensure_authenticated_locked()
            return await self._send_v2_locked(frame, context=context)

    async def _send_v2_locked(self, frame: bytes, context: str | None = None) -> ParsedFrame:
        """Envia ``frame`` e lê a resposta — assume o lock já adquirido."""
        rotulo = f" [{context}]" if context else ""
        assert self._reader is not None and self._writer is not None
        try:
            _LOGGER.debug("ANM 24 G2: enviando%s: %s", rotulo, frame.hex(" ").upper())
            self._writer.write(frame)
            await self._writer.drain()

            # Cabeçalho fixo de 6 bytes; o tamanho do corpo vem nos dois
            # últimos, e a partir dele sabemos quanto ainda falta ler.
            cabecalho = await asyncio.wait_for(
                self._reader.readexactly(6), timeout=self._timeout
            )
            tamanho = (cabecalho[4] << 8) | cabecalho[5]
            resto = await asyncio.wait_for(
                self._reader.readexactly(tamanho + 1), timeout=self._timeout
            )
            raw = cabecalho + resto
        except asyncio.TimeoutError as err:
            await self._close_locked()
            raise Anm24ConnectionError(
                f"Falha de comunicação com a central{rotulo}: tempo limite de "
                f"{self._timeout}s excedido"
            ) from err
        except asyncio.IncompleteReadError as err:
            await self._close_locked()
            raise Anm24ConnectionError(
                f"Falha de comunicação com a central{rotulo}: conexão encerrada antes "
                f"da resposta completa (esperado {err.expected}, recebido "
                f"{len(err.partial)} bytes)"
            ) from err
        except OSError as err:
            await self._close_locked()
            raise Anm24ConnectionError(
                f"Falha de comunicação com a central{rotulo}: {err or err.__class__.__name__}"
            ) from err

        try:
            resposta = parse_frame(raw)
        except Anm24ProtocolError as err:
            raise Anm24ConnectionError(f"{err}{rotulo}") from err

        if not resposta.valid_checksum:
            _LOGGER.warning(
                "ANM 24 G2: checksum inválido na resposta%s: %s", rotulo, raw.hex(" ").upper()
            )
        return resposta
