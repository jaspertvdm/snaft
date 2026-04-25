"""
SNAFT Encoded Decoder — utilities voor SNAFT-023-ENCODED-INJECTION.

Storm Discovery (2026-04-24): LLM safety filters worden bypassed wanneer
een payload als binary/hex/base64 wordt aangeleverd. Het model decodeert
intern, zegt rustig wat anders zou worden geblokkeerd. Deze module geeft
de bouwstenen voor SNAFT om die paydoor dicht te timmeren:

    1. Snel detecteren of input lijkt op een encoded payload.
    2. Veilig (depth-bounded) decoderen — niet de hele Mariana Trench in.
    3. Magic-bytes herkennen — een PNG-blob in een tekstprompt is verdacht.
    4. UTF-8 strict + printable-ratio filter zodat random binaire ruis en
       JWT/UUID-look-alikes niet als tekst-injection worden aangezien.

Ontwerp-principes:
- Defense in depth: meerdere goedkope filters voor één dure injection scan.
- Anti-DoS: harde size cap (50KB), bounded recursion (3 lagen), geen ReDoS-
  kwetsbare patronen.
- False-positive vermindering: JWT, UUID, sessiontokens lijken op base64/hex —
  ze passeren als ze niet decoderen tot leesbare ASCII met injection-markers.
"""

import base64
import re
import string
from typing import List, Optional, Tuple


# ─── Configuratie ────────────────────────────────────────────────────────────
MAX_PAYLOAD_SIZE = 50 * 1024  # 50 KB hard cap (anti-DoS)
MAX_DECODE_DEPTH = 3           # Geen oneindige decode-loops
PRINTABLE_THRESHOLD = 0.8      # Minimaal aandeel printable chars na decode

# ─── Patterns voor detect_encoding ──────────────────────────────────────────
# Binary: minstens 40 chars van enkel 0/1/whitespace
_BINARY_RE = re.compile(r"^[01\s]+$")

# Hex: minstens 40 chars van 0-9a-fA-F (eventueel met whitespace tussen bytes)
_HEX_RE = re.compile(r"^[0-9a-fA-F\s]+$")

# Base64: minimaal 20 chars uit base64 alfabet, valid padding tot een 4-mod
# (we zijn streng: lege/ruisvolle base64-look strings vallen hier door de mand)
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

# Magic bytes — eerste paar bytes herkennen als bekend bestandstype
_MAGIC_BYTES = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF-",             "pdf"),
    (b"\xff\xd8\xff",      "jpeg"),
    (b"GIF87a",            "gif"),
    (b"GIF89a",            "gif"),
    (b"PK\x03\x04",        "zip"),  # ook docx/xlsx/jar
    (b"\x1f\x8b\x08",      "gzip"),
    (b"\x00\x00\x00",      "mp4_or_iso"),  # zwakker, dekt diverse ISO BMFF types
    (b"RIFF",              "riff"),         # WAV, AVI, WebP
    (b"OggS",              "ogg"),
    (b"ID3",               "mp3"),
    (b"\x7fELF",           "elf"),          # Linux executable!
    (b"MZ",                "pe"),           # Windows executable!
]


# ─── Detectie ────────────────────────────────────────────────────────────────
def detect_encoding(text: str) -> Optional[str]:
    """Return 'binary' | 'hex' | 'base64' wanneer text er als zo'n payload uitziet.

    Heuristiek; niet bewijzend. False positives op JWT/UUID worden later
    afgevangen via UTF-8 strict + printable ratio.
    """
    if not text or len(text) < 20:
        return None

    stripped = text.strip()
    no_ws = re.sub(r"\s+", "", stripped)

    # Binary heeft veel witruimte tussen bytes; check met whitespace.
    if _BINARY_RE.match(stripped) and len(no_ws) >= 40 and set(no_ws) <= {"0", "1"}:
        # Aantal bits moet door 8 deelbaar zijn voor zinvolle decode
        if len(no_ws) % 8 == 0:
            return "binary"

    # Hex: alleen 0-9a-fA-F, even aantal nibbles
    if _HEX_RE.match(stripped) and len(no_ws) >= 40 and len(no_ws) % 2 == 0:
        # Filter out alles-nullen / alles-één-char (waarschijnlijk geen payload)
        if len(set(no_ws.lower())) >= 4:
            return "hex"

    # Base64: minimaal 20 chars, valid alfabet incl. padding
    if _BASE64_RE.match(no_ws) and len(no_ws) >= 20 and len(no_ws) % 4 == 0:
        # Filter UUID-look (32 hex chars in 8-4-4-4-12) — die match _HEX_RE eerder
        # Filter "alleen letters" (waarschijnlijk geen payload, gewone tekst die
        # toevallig in base64-alfabet zit zoals "HelloWorldFooBar")
        char_classes = sum([
            any(c.isupper() for c in no_ws),
            any(c.islower() for c in no_ws),
            any(c.isdigit() for c in no_ws),
        ])
        if char_classes >= 2:  # Mix vereist — anders valt natuurlijke text in
            return "base64"

    return None


def magic_bytes_detect(payload: bytes) -> Optional[str]:
    """Return label van bekend bestandstype als bytes met die signature beginnen.

    Een PNG-blob of ELF-executable in een chat-prompt is per definitie
    verdacht — geen text-injection, wel iets dat downstream niet hoort.
    """
    if not payload:
        return None
    for sig, label in _MAGIC_BYTES:
        if payload.startswith(sig):
            return label
    return None


# ─── Decode-pogingen ─────────────────────────────────────────────────────────
def _try_decode_binary(text: str) -> Optional[bytes]:
    """Binair (8-bit per byte, whitespace toegestaan) → bytes."""
    no_ws = re.sub(r"\s+", "", text)
    if not no_ws or len(no_ws) % 8 != 0:
        return None
    try:
        return bytes(int(no_ws[i:i + 8], 2) for i in range(0, len(no_ws), 8))
    except ValueError:
        return None


def _try_decode_hex(text: str) -> Optional[bytes]:
    """Hex → bytes."""
    no_ws = re.sub(r"\s+", "", text)
    if not no_ws or len(no_ws) % 2 != 0:
        return None
    try:
        return bytes.fromhex(no_ws)
    except ValueError:
        return None


def _try_decode_base64(text: str) -> Optional[bytes]:
    """Base64 → bytes (strict: validate=True)."""
    no_ws = re.sub(r"\s+", "", text)
    if not no_ws:
        return None
    try:
        return base64.b64decode(no_ws, validate=True)
    except (ValueError, base64.binascii.Error):
        return None


_DECODERS = {
    "binary": _try_decode_binary,
    "hex": _try_decode_hex,
    "base64": _try_decode_base64,
}


def recursive_decode(
    text: str,
    max_depth: int = MAX_DECODE_DEPTH,
) -> List[Tuple[str, bytes]]:
    """Pel encoded lagen af (max_depth diep).

    Returns list van (encoding_label, decoded_bytes) per laag, in volgorde
    waarin gepeld. Lege list = geen encoding gedetecteerd / decode mislukt
    op de eerste poging.

    Bij elke laag wordt de gedecodeerde bytes geprobeerd te interpreteren als
    UTF-8 tekst; lukt dat én ziet die tekst er zelf uit als nog een encoding,
    dan pellen we verder. Anders stoppen we.
    """
    if not text or len(text) > MAX_PAYLOAD_SIZE:
        return []

    layers: List[Tuple[str, bytes]] = []
    current = text

    for _ in range(max_depth):
        encoding = detect_encoding(current)
        if encoding is None:
            break

        decoder = _DECODERS.get(encoding)
        if decoder is None:
            break

        decoded = decoder(current)
        if decoded is None:
            break

        layers.append((encoding, decoded))

        # Probeer als UTF-8 tekst te interpreteren voor verdere recursie.
        try:
            current = decoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # Decoded ≠ tekst → niets meer te pellen
            break

    return layers


# ─── Tekst-classificatie ─────────────────────────────────────────────────────
def is_printable_text(text: str, threshold: float = PRINTABLE_THRESHOLD) -> bool:
    """True als minstens `threshold` (default 80%) van text printable is.

    Filtert obfuscation aanvallen waarbij valid UTF-8 wordt gemixt met
    control chars / zero-width chars om filters te ontwijken.
    """
    if not text:
        return False
    printable_chars = sum(1 for c in text if c in string.printable)
    return (printable_chars / len(text)) >= threshold
