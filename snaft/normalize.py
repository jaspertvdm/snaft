"""
SNAFT Input Normalization — Defeat encoding-based bypass attacks.

Attackers use Unicode confusables (Greek Alpha instead of Latin A),
zero-width characters, null bytes, and mixed encodings to evade
pattern-based detection. This module normalizes input before analysis.

Battle-tested against NIGHTFALL pentest engagement (RS-2026-001):
    - Greek/Cyrillic homoglyphs (Α→A, Ν→N, С→C)
    - Zero-width joiners/spaces (\u200b, \u200c, \u200d)
    - Null byte injection (\x00)
    - Vertical tab / form feed whitespace (\x0b, \x0c)
    - Triple URL encoding (%252520)
    - NFKC fullwidth bypasses (Ａ→A)

Usage:
    from snaft.normalize import normalize

    clean = normalize("SELECT * FROM users")          # passthrough
    clean = normalize("S\\u0395LECT * FR\\u039fM users")  # Greek E,O → Latin
    clean = normalize("AND\\u200b0=0")                 # zero-width → space
"""

import re
import unicodedata
from typing import Optional

__all__ = ["normalize", "strip_dangerous_chars", "normalize_confusables"]

# Greek/Cyrillic → Latin confusable mapping
# Only uppercase because input is typically lowercased before pattern matching,
# but we normalize BEFORE lowering so we need the uppercase forms.
_CONFUSABLE_MAP = str.maketrans({
    # Greek uppercase that look like Latin
    '\u0391': 'A',  # Alpha
    '\u0392': 'B',  # Beta
    '\u0395': 'E',  # Epsilon
    '\u0396': 'Z',  # Zeta
    '\u0397': 'H',  # Eta
    '\u0399': 'I',  # Iota
    '\u039a': 'K',  # Kappa
    '\u039c': 'M',  # Mu
    '\u039d': 'N',  # Nu
    '\u039f': 'O',  # Omicron
    '\u03a1': 'P',  # Rho
    '\u03a4': 'T',  # Tau
    '\u03a5': 'Y',  # Upsilon
    '\u03a7': 'X',  # Chi
    # Greek lowercase
    '\u03bf': 'o',  # omicron
    '\u03b1': 'a',  # alpha (looks similar in some fonts)
    # Cyrillic uppercase
    '\u0410': 'A',  # А
    '\u0412': 'B',  # В (Ve)
    '\u0415': 'E',  # Е (Ie)
    '\u041a': 'K',  # К (Ka)
    '\u041c': 'M',  # М (Em)
    '\u041d': 'H',  # Н (En)
    '\u041e': 'O',  # О
    '\u0420': 'P',  # Р (Er)
    '\u0421': 'C',  # С (Es)
    '\u0422': 'T',  # Т (Te)
    '\u0423': 'Y',  # У (U)
    '\u0425': 'X',  # Х (Ha)
    # Cyrillic lowercase
    '\u0430': 'a',  # а
    '\u0435': 'e',  # е
    '\u043e': 'o',  # о
    '\u0440': 'p',  # р
    '\u0441': 'c',  # с
    '\u0443': 'y',  # у
    '\u0445': 'x',  # х
})

# Zero-width and invisible characters (replaced with space to preserve word boundaries)
_INVISIBLE_PATTERN = re.compile(
    '['
    '\u200b-\u200f'  # zero-width space, joiner, non-joiner, LTR/RTL marks
    '\u2028-\u202f'  # line/paragraph separators, embedding controls
    '\ufeff'         # BOM / zero-width no-break space
    '\u00ad'         # soft hyphen
    '\u034f'         # combining grapheme joiner
    '\u180e'         # Mongolian vowel separator
    '\u2060-\u2064'  # word joiner, invisible operators
    '\u2066-\u206f'  # bidi controls
    ']'
)


def strip_dangerous_chars(text: str) -> str:
    """Remove null bytes and replace invisible Unicode with spaces.

    Null bytes are stripped entirely (never valid in text).
    Invisible characters become spaces to preserve word boundaries:
    "AND\\u200b0=0" becomes "AND 0=0", not "AND0=0".
    """
    # Null bytes — always strip
    text = text.replace('\x00', '')
    # Invisible characters — replace with space
    text = _INVISIBLE_PATTERN.sub(' ', text)
    # Control characters (vertical tab, form feed) — replace with space
    text = re.sub('[\x0b\x0c]', ' ', text)
    # Collapse multiple spaces
    text = re.sub(r'  +', ' ', text)
    return text


def normalize_confusables(text: str) -> str:
    """Replace Unicode confusable characters with their Latin equivalents.

    Greek Alpha (Α) → A, Cyrillic Es (С) → C, etc.
    Combined with NFKC normalization for fullwidth characters.
    """
    # NFKC: maps fullwidth (Ａ→A), compatibility forms, composed characters
    text = unicodedata.normalize('NFKC', text)
    # Homoglyph replacement
    text = text.translate(_CONFUSABLE_MAP)
    return text


def normalize(text: str, url_decode: bool = False) -> str:
    """Full normalization pipeline for security analysis.

    1. Optional URL decoding (for query strings)
    2. Strip null bytes and dangerous chars
    3. Replace invisible Unicode with spaces
    4. NFKC normalization
    5. Replace confusable Greek/Cyrillic with Latin

    Args:
        text: Input text to normalize
        url_decode: If True, URL-decode first (for query parameters)

    Returns:
        Normalized text safe for pattern matching
    """
    if not text:
        return text

    # Optional URL decode
    if url_decode:
        from urllib.parse import unquote
        text = unquote(text)

    # Strip dangerous characters
    text = strip_dangerous_chars(text)

    # Normalize confusables (includes NFKC)
    text = normalize_confusables(text)

    return text
