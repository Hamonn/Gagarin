# crypto_module.py
import os
import json
import base64
import hashlib
import struct
import sys
import ctypes
from dataclasses import dataclass
from typing import Tuple, Dict, Any, Optional, Iterator, Callable

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Попытка поддержки XChaCha
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    HAS_XCHACHA = True
except Exception:
    XChaCha20Poly1305 = None
    HAS_XCHACHA = False

# Доступность DPAPI
USE_DPAPI = False
if sys.platform.startswith("win"):
    try:
        import ctypes.wintypes as wintypes
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        USE_DPAPI = True
    except Exception:
        USE_DPAPI = False

MAGIC = b"ENCRv2"            # формат/версия
SALT_LEN = 16
AES_NONCE_LEN = 12
CHACHA_NONCE_LEN = 12
XCHACHA_NONCE_LEN = 24
KEY_LEN = 32

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
KDF_ITERATIONS_DEFAULT = 200_000
KDF_ITERATIONS_FAST = 25_000

# Тип функции обратного вызова для прогресса
ProgressCB = Optional[Callable[[int, Optional[int]], None]]  # (bytes_done, total_bytes или None)

class CryptoError(Exception):
    pass

# ---------- Вспомогательные функции DPAPI (Windows) ----------
if USE_DPAPI:
    import ctypes.wintypes as wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def _dpapi_protect(data: bytes) -> bytes:
        # Защита данных с помощью DPAPI
        blob_in = DATA_BLOB()
        blob_in.cbData = len(data)
        blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte))
        blob_out = DATA_BLOB()
        if not crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            raise CryptoError("Не удалось выполнить CryptProtectData")
        buf = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        kernel32.LocalFree(blob_out.pbData)
        return buf

    def _dpapi_unprotect(data: bytes) -> bytes:
        # Расшифровка данных с помощью DPAPI
        blob_in = DATA_BLOB()
        blob_in.cbData = len(data)
        blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte))
        blob_out = DATA_BLOB()
        if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            raise CryptoError("Не удалось выполнить CryptUnprotectData")
        buf = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        kernel32.LocalFree(blob_out.pbData)
        return buf
else:
    def _dpapi_protect(data: bytes) -> bytes:
        # DPAPI недоступен на этой платформе
        raise CryptoError("DPAPI недоступен на этой платформе")
    def _dpapi_unprotect(data: bytes) -> bytes:
        # DPAPI недоступен на этой платформе
        raise CryptoError("DPAPI недоступен на этой платформе")

# ---------- KSP / TPM (заглушка с попыткой) ----------
def try_store_to_windows_ksp(name: str, secret: bytes) -> bool:
    """
    Попытка сохранить секрет в Windows KSP (CNG) - наилучшее усилие.
    Эта функция использует ctypes и CNG API. На большинстве машин может не работать
    из-за прав/наличия провайдера. Возвращает True если успешно, False если нет.
    (Не бросает исключение, только логическую ошибку).
    """
    # Реализация полноценной интеграции с KSP выходит за рамки небольшого модуля.
    # Здесь — заглушка: пробуем вызвать NCryptOpenStorageProvider / NCryptCreatePersistedKey ...
    # Если не удалось, просто возвращаем False.
    try:
        if not sys.platform.startswith("win"):
            return False
        # Попытка загрузки ncrypt.dll
        ncrypt = ctypes.WinDLL("ncrypt.dll")
        # Реализация сложная и непостоянная — поэтому не делаем полноценного flow.
        # Возвращаем False, что указывает на отсутствие поддержки.
        return False
    except Exception:
        return False

def try_retrieve_from_windows_ksp(name: str) -> Optional[bytes]:
    """Попытка получить секрет из KSP — заглушка."""
    return None

# ---------- Утилиты (KDF / упаковка) ----------
def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    # Вывод ключа из пароля с помощью PBKDF2
    if not isinstance(password, str):
        raise CryptoError("Пароль должен быть строкой")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def _pack_blob(salt: bytes, nonce: bytes, header_json: bytes, ciphertext: bytes) -> bytes:
    # Упаковка данных: MAGIC | salt | nonce_len(1) | nonce | header_len(4BE) | header_json | ciphertext
    nonce_len_b = len(nonce).to_bytes(1, byteorder="big")
    header_len_b = len(header_json).to_bytes(4, byteorder="big")
    blob = MAGIC + salt + nonce_len_b + nonce + header_len_b + header_json + ciphertext
    return base64.b64encode(blob)

def _unpack_blob(raw_b64: bytes) -> Tuple[bytes, bytes, bytes, Dict[str, Any], bytes]:
    # Распаковка данных
    try:
        blob = base64.b64decode(raw_b64)
    except Exception as e:
        raise CryptoError("Недопустимый base64") from e
    if not blob.startswith(MAGIC):
        raise CryptoError("Несоответствие магического числа")
    idx = len(MAGIC)
    salt = blob[idx: idx + SALT_LEN]; idx += SALT_LEN
    nonce_len = blob[idx]; idx += 1
    nonce = blob[idx: idx + nonce_len]; idx += nonce_len
    header_len = int.from_bytes(blob[idx: idx + 4], byteorder="big"); idx += 4
    header_json = blob[idx: idx + header_len]; idx += header_len
    ciphertext = blob[idx:]
    try:
        header = json.loads(header_json.decode("utf-8"))
    except Exception as e:
        raise CryptoError("Ошибка разбора JSON заголовка") from e
    return salt, nonce, header_json, header, ciphertext

# ---------- Вспомогательные функции для потока ----------
def _pack_stream_blocks(blocks: Iterator[Tuple[int, bytes, bytes]]) -> bytes:
    # Упаковка блоков потока
    parts = []
    count = 0
    for plain_len, ct, nonce in blocks:
        parts.append(struct.pack(">I", plain_len))
        parts.append(struct.pack(">I", len(ct)))
        parts.append(struct.pack("B", len(nonce)))
        parts.append(nonce)
        parts.append(ct)
        count += 1
    header = struct.pack(">I", count)
    return header + b"".join(parts)

def _unpack_stream_blocks(stream_blob: bytes) -> Iterator[Tuple[int, bytes, bytes]]:
    # Распаковка блоков потока
    idx = 0
    if len(stream_blob) < 4:
        raise CryptoError("Поток поврежден (нет заголовка)")
    count = int.from_bytes(stream_blob[idx: idx + 4], byteorder="big"); idx += 4
    for _ in range(count):
        if len(stream_blob) < idx + 4:
            raise CryptoError("Поток поврежден (нет plain_len)")
        plain_len = int.from_bytes(stream_blob[idx: idx + 4], byteorder="big"); idx += 4
        ct_len = int.from_bytes(stream_blob[idx: idx + 4], byteorder="big"); idx += 4
        nonce_len = stream_blob[idx]; idx += 1
        nonce = stream_blob[idx: idx + nonce_len]; idx += nonce_len
        ct = stream_blob[idx: idx + ct_len]; idx += ct_len
        yield plain_len, ct, nonce

# ---------- Парсер старого формата (для конвертера) ----------
def parse_old_format(b64_blob: bytes) -> Tuple[bytes, bytes, bytes, Dict[str, Any], bytes]:
    """
    Старый формат (по описанию в первом коде пользователя):
    base64(salt + iv + tag + meta_json + b'|' + encrypted_data)
    Где:
      - salt: 16
      - iv: 12 (GCM) или 16 (CBC), но тег у GCM = 16 байт
    Функция пытается детектировать структуру: ищет '|' разделитель после meta_json.
    Возвращает (salt, iv, tag, meta_dict, encrypted_data)
    """
    try:
        blob = base64.b64decode(b64_blob)
    except Exception:
        raise CryptoError("Старый файл: недопустимый base64")
    # ищем разделитель '|' (0x7C)
    sep_idx = blob.find(b'|')
    if sep_idx == -1:
        raise CryptoError("Старый файл: разделитель '|' не найден")
    meta_start = None
    # предполагаем, что salt первые 16 байт
    salt = blob[:16]
    # оставшаяся часть до '|' включает iv + tag + meta_json
    remainder = blob[16:sep_idx]
    # предполагаем, что meta_json начинается с '{' и кончается '}' — ищем ближайший '{' в remainder
    brace_idx = remainder.find(b'{')
    if brace_idx == -1:
        raise CryptoError("Старый файл: JSON заголовок не найден")
    # тогда iv+tag = remainder[:brace_idx], meta_json = remainder[brace_idx:]
    iv_tag = remainder[:brace_idx]
    meta_json = remainder[brace_idx:]
    encrypted_data = blob[sep_idx + 1:]
    # Разделим iv_tag на iv и tag - попробуем несколько вариантов
    # Если len(iv_tag) >= 28 -> возможно GCM: iv=12 tag=16
    iv = b''
    tag = b''
    if len(iv_tag) >= 28:
        iv = iv_tag[:12]
        tag = iv_tag[12:28]
    else:
        # fallback: если iv_tag len 16 -> iv=16 (CBC), tag пустой
        if len(iv_tag) == 16:
            iv = iv_tag
            tag = b''
        elif len(iv_tag) >= 12:
            iv = iv_tag[:12]
            tag = iv_tag[12:]
        else:
            raise CryptoError("Старый файл: невозможно определить длину iv/tag")
    try:
        meta = json.loads(meta_json.decode("utf-8"))
    except Exception as e:
        raise CryptoError("Старый файл: ошибка разбора JSON заголовка") from e
    return salt, iv, tag, meta, encrypted_data

# ---------- Основной класс ----------
@dataclass
class CryptoModuleOptions:
    method: str = "AES-256-GCM"
    timer_seconds: int = 0
    copy_protection: bool = False
    bind_to_ip_mac: bool = False
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    max_opens: int = 5
    restrict_modification: bool = False
    restrict_move: bool = False
    kdf_iterations: int = KDF_ITERATIONS_DEFAULT
    streaming_chunk_size: int = DEFAULT_CHUNK_SIZE
    streaming: bool = False

class CryptoModule:
    def __init__(self):
        pass

    # ---------- Шифрование файла с прогрессом ----------
    def encrypt_file(self,
                     file_path: str,
                     password: str,
                     progress_callback: ProgressCB = None,
                     **opts) -> str:
        """
        progress_callback(bytes_processed, total_bytes_or_None)
        Опции как в предыдущей версии: method, streaming, kdf_iterations, streaming_chunk_size и пр.
        """
        # Шифрование файла с учетом прогресса
        if not os.path.exists(file_path):
            raise ValueError("Файл не найден")
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Пароль должен быть строкой длиной >=8")

        method = opts.get("method", "AES-256-GCM")
        if method == "XChaCha20-Poly1305" and not HAS_XCHACHA:
            method = "ChaCha20-Poly1305"

        kdf_iterations = int(opts.get("kdf_iterations", KDF_ITERATIONS_DEFAULT))
        streaming = bool(opts.get("streaming", False))
        chunk_size = int(opts.get("streaming_chunk_size", DEFAULT_CHUNK_SIZE))

        total_size = os.path.getsize(file_path)
        done = 0

        if streaming:
            # Шифрование в потоковом режиме
            salt = os.urandom(SALT_LEN)
            key = _derive_key(password, salt, kdf_iterations)
            header = {
                "method": method,
                "streaming": True,
                "chunk_size": chunk_size,
                "timer": int(opts.get("timer_seconds", 0)),
                "copy_protection": bool(opts.get("copy_protection", False)),
                "bind": bool(opts.get("bind_to_ip_mac", False)),
                "device_id": opts.get("device_id"),
                "ip_address": opts.get("ip_address"),
                "mac_address": opts.get("mac_address"),
                "max_opens": int(opts.get("max_opens", 5)),
                "current_opens": 0,
                "restrict_modification": bool(opts.get("restrict_modification", False)),
                "restrict_move": bool(opts.get("restrict_move", False)),
                "original_name": os.path.basename(file_path),
                "format_version": 2
            }
            header_json = json.dumps(header, ensure_ascii=False).encode("utf-8")

            if method == "AES-256-GCM":
                base_nonce = os.urandom(AES_NONCE_LEN)
                aead_cls = AESGCM
                nonce_len = AES_NONCE_LEN
            elif method == "XChaCha20-Poly1305":
                base_nonce = os.urandom(XCHACHA_NONCE_LEN)
                aead_cls = XChaCha20Poly1305 if HAS_XCHACHA else ChaCha20Poly1305
                nonce_len = XCHACHA_NONCE_LEN if HAS_XCHACHA else CHACHA_NONCE_LEN
            else:
                base_nonce = os.urandom(CHACHA_NONCE_LEN)
                aead_cls = ChaCha20Poly1305
                nonce_len = CHACHA_NONCE_LEN

            aead = aead_cls(key)
            blocks = []
            counter = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    # вывод nonce
                    if nonce_len >= 8:
                        last8 = int.from_bytes(base_nonce[-8:], byteorder="big")
                        new_last8 = (last8 + counter) & ((1 << 64) - 1)
                        nonce = base_nonce[:-8] + new_last8.to_bytes(8, byteorder="big")
                    else:
                        nonce = base_nonce[:nonce_len - 4] + counter.to_bytes(4, byteorder="big")
                    ct = aead.encrypt(nonce, chunk, header_json)
                    blocks.append((len(chunk), ct, nonce))
                    counter += 1
                    done += len(chunk)
                    if progress_callback:
                        try:
                            progress_callback(done, total_size)
                        except Exception:
                            pass

            stream_blob = _pack_stream_blocks(iter(blocks))
            out_blob = _pack_blob(salt, base_nonce, header_json, stream_blob)
            out_path = file_path + ".enc"
            with open(out_path, "wb") as outf:
                outf.write(out_blob)
            if progress_callback:
                try:
                    progress_callback(total_size, total_size)
                except Exception:
                    pass
            return out_path

        else:
            # Шифрование в непотоковом режиме
            with open(file_path, "rb") as f:
                plaintext = f.read()
            salt = os.urandom(SALT_LEN)
            key = _derive_key(password, salt, kdf_iterations)
            header = {
                "method": method,
                "streaming": False,
                "timer": int(opts.get("timer_seconds", 0)),
                "copy_protection": bool(opts.get("copy_protection", False)),
                "bind": bool(opts.get("bind_to_ip_mac", False)),
                "device_id": opts.get("device_id"),
                "ip_address": opts.get("ip_address"),
                "mac_address": opts.get("mac_address"),
                "max_opens": int(opts.get("max_opens", 5)),
                "current_opens": 0,
                "restrict_modification": bool(opts.get("restrict_modification", False)),
                "restrict_move": bool(opts.get("restrict_move", False)),
                "original_name": os.path.basename(file_path),
                "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                "plaintext_size": len(plaintext),
                "format_version": 2
            }
            header_json = json.dumps(header, ensure_ascii=False).encode("utf-8")

            if method == "AES-256-GCM":
                nonce = os.urandom(AES_NONCE_LEN)
                aead = AESGCM(key)
            elif method == "XChaCha20-Poly1305":
                nonce = os.urandom(XCHACHA_NONCE_LEN)
                aead = XChaCha20Poly1305(key) if HAS_XCHACHA else ChaCha20Poly1305(key)
            else:
                nonce = os.urandom(CHACHA_NONCE_LEN)
                aead = ChaCha20Poly1305(key)

            ciphertext = aead.encrypt(nonce, plaintext, header_json)
            out_blob = _pack_blob(salt, nonce, header_json, ciphertext)
            out_path = file_path + ".enc"
            with open(out_path, "wb") as outf:
                outf.write(out_blob)
            if progress_callback:
                try:
                    progress_callback(len(plaintext), len(plaintext))
                except Exception:
                    pass
            return out_path

    # ---------- Расшифровка файла с прогрессом ----------
    def decrypt_file(self,
                     file_path: str,
                     password: str,
                     output_path: str,
                     progress_callback: ProgressCB = None) -> Tuple[str, Dict[str, Any]]:
        # Расшифровка файла с учетом прогресса
        if not os.path.exists(file_path):
            raise ValueError("Файл не найден")
        raw = open(file_path, "rb").read()
        salt, nonce, header_json, header, ciphertext = _unpack_blob(raw)
        kdf_iterations = header.get("kdf_iterations", KDF_ITERATIONS_DEFAULT)
        try:
            key = _derive_key(password, salt, kdf_iterations)
        except Exception as e:
            raise CryptoError("Ошибка KDF") from e

        method = header.get("method", "AES-256-GCM")
        streaming = bool(header.get("streaming", False))

        if streaming:
            # Расшифровка в потоковом режиме
            blocks = list(_unpack_stream_blocks(ciphertext))
            total_plain = sum(b[0] for b in blocks)
            done = 0
            # Проверка количества открытий
            if header.get("current_opens", 0) >= header.get("max_opens", 5):
                raise ValueError("Превышено максимальное количество открытий")
            # Выбор класса AEAD
            if method == "AES-256-GCM":
                aead_cls = AESGCM
            elif method == "XChaCha20-Poly1305":
                aead_cls = XChaCha20Poly1305 if HAS_XCHACHA else ChaCha20Poly1305
            else:
                aead_cls = ChaCha20Poly1305
            aead = aead_cls(key)
            with open(output_path, "wb") as outf:
                for plain_len, ct, blk_nonce in blocks:
                    try:
                        chunk_plain = aead.decrypt(blk_nonce, ct, header_json)
                    except InvalidTag:
                        raise ValueError("Неверный пароль или поврежденный блок в потоке")
                    outf.write(chunk_plain)
                    done += plain_len
                    if progress_callback:
                        try:
                            progress_callback(done, total_plain)
                        except Exception:
                            pass
            # Повторное шифрование с увеличенным счетчиком
            header["current_opens"] = header.get("current_opens", 0) + 1
            new_header_json = json.dumps(header, ensure_ascii=False).encode("utf-8")
            new_base_nonce = os.urandom(len(nonce))
            new_aead = aead_cls(key)
            # Повторное шифрование из output_path
            blocks_out = []
            with open(output_path, "rb") as fin:
                counter = 0
                chunk_size = header.get("chunk_size", DEFAULT_CHUNK_SIZE)
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    nonce_len = len(new_base_nonce)
                    if nonce_len >= 8:
                        last8 = int.from_bytes(new_base_nonce[-8:], byteorder="big")
                        new_last8 = (last8 + counter) & ((1 << 64) - 1)
                        blk_nonce = new_base_nonce[:-8] + new_last8.to_bytes(8, byteorder="big")
                    else:
                        blk_nonce = new_base_nonce[:nonce_len - 4] + counter.to_bytes(4, byteorder="big")
                    ct = new_aead.encrypt(blk_nonce, chunk, new_header_json)
                    blocks_out.append((len(chunk), ct, blk_nonce))
                    counter += 1
            new_stream_blob = _pack_stream_blocks(iter(blocks_out))
            new_blob = _pack_blob(salt, new_base_nonce, new_header_json, new_stream_blob)
            with open(file_path, "wb") as fw:
                fw.write(new_blob)
            if progress_callback:
                try:
                    progress_callback(total_plain, total_plain)
                except Exception:
                    pass
            return output_path, header

        else:
            # Расшифровка в непотоковом режиме
            if method == "AES-256-GCM":
                aead = AESGCM(key)
            elif method == "XChaCha20-Poly1305":
                aead = XChaCha20Poly1305(key) if HAS_XCHACHA else ChaCha20Poly1305(key)
            else:
                aead = ChaCha20Poly1305(key)
            try:
                plaintext = aead.decrypt(nonce, ciphertext, header_json)
            except InvalidTag:
                raise ValueError("Неверный пароль или поврежденный файл")
            if header.get("current_opens", 0) >= header.get("max_opens", 5):
                raise ValueError("Превышено максимальное количество открытий")
            with open(output_path, "wb") as fout:
                fout.write(plaintext)
            header["current_opens"] = header.get("current_opens", 0) + 1
            new_header_json = json.dumps(header, ensure_ascii=False).encode("utf-8")
            if method == "AES-256-GCM":
                new_nonce = os.urandom(AES_NONCE_LEN)
                new_aead = AESGCM(key)
            elif method == "XChaCha20-Poly1305":
                new_nonce = os.urandom(XCHACHA_NONCE_LEN)
                new_aead = XChaCha20Poly1305(key) if HAS_XCHACHA else ChaCha20Poly1305(key)
            else:
                new_nonce = os.urandom(CHACHA_NONCE_LEN)
                new_aead = ChaCha20Poly1305(key)
            new_ct = new_aead.encrypt(new_nonce, plaintext, new_header_json)
            new_blob = _pack_blob(salt, new_nonce, new_header_json, new_ct)
            with open(file_path, "wb") as fw:
                fw.write(new_blob)
            if progress_callback:
                try:
                    progress_callback(len(plaintext), len(plaintext))
                except Exception:
                    pass
            return output_path, header

    # ---------- Конвертация старого формата в новый ----------
    def convert_old_to_new(self, old_file_path: str, password: str, out_path: Optional[str] = None) -> str:
        """
        Читает файл в старом формате (описан в предыдущей версии), проверяет пароль,
        и записывает в новый формат ENCRv2 (streaming=false). Возвращает путь нового файла.
        """
        if not os.path.exists(old_file_path):
            raise ValueError("Старый файл не найден")
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Пароль должен быть строкой длиной >=8")
        raw = open(old_file_path, "rb").read()
        try:
            salt, iv, tag, meta, encrypted_data = parse_old_format(raw)
        except CryptoError as e:
            raise ValueError("Не удается разобрать старый формат: " + str(e))

        # Вывод ключа и расшифровка по старому методу
        method = meta.get("method", "AES-256-GCM")
        kdf_iterations = meta.get("kdf_iterations", KDF_ITERATIONS_DEFAULT)
        key = _derive_key(password, salt, kdf_iterations)

        # Попытка расшифровки старого файла
        try:
            if method == "AES-256-GCM":
                aead = AESGCM(key)
                # Восстановление шифрованного текста: encrypted_data вероятно НЕ содержит tag
                ct_with_tag = encrypted_data + tag if tag else encrypted_data
                plaintext = aead.decrypt(iv, ct_with_tag, json.dumps(meta).encode())
            elif method == "AES-256-CBC":
                # CBC в старом формате: использует PKCS7 padding
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives import padding
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded) + unpadder.finalize()
            else:
                # ChaCha20 (старый) - в старом коде использовался algorithms.ChaCha20(key, iv)
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
        except Exception as e:
            raise ValueError("Не удается расшифровать старый файл (неверный пароль или формат): " + str(e))

        # Повторное шифрование в новом формате (непотоковом) с параметрами по умолчанию
        if out_path is None:
            out_path = old_file_path + ".v2.enc"
        new_options = {
            "method": method if method in ("AES-256-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305") else "AES-256-GCM",
            "kdf_iterations": KDF_ITERATIONS_DEFAULT,
            "timer_seconds": meta.get("timer", 0),
            "copy_protection": meta.get("copy_protection", False),
            "bind_to_ip_mac": meta.get("bind", False),
            "device_id": meta.get("device_id"),
            "ip_address": meta.get("ip_address"),
            "mac_address": meta.get("mac_address"),
            "max_opens": meta.get("max_opens", 5),
            "restrict_modification": meta.get("restrict_modification", False),
            "restrict_move": meta.get("restrict_move", False),
        }
        # Запись открытого текста во временный файл и вызов encrypt_file для согласованного поведения
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(plaintext)
            tf_path = tf.name
        try:
            new_path = self.encrypt_file(tf_path, password, **new_options)
            # Перемещение new_path в out_path
            os.replace(new_path, out_path)
        finally:
            try:
                os.remove(tf_path)
            except Exception:
                pass
        return out_path

    # ---------- Экспорт/Импорт мастер-ключа с DPAPI / KSP попытками ----------
    def export_key(self, password: str, out_path: str, protect_with_dpapi: bool = True, try_ksp: bool = False) -> str:
        """
        Экспорт мастер-ключа: возвращает путь к файлу.
        Попытка сохранить секрет в KSP выполняется только если try_ksp=True и KSP доступен.
        Если try_ksp сработает - файл будет содержать ссылка/маркер (плейсхолдер).
        """
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Пароль должен быть строкой длиной >=8")
        master_key = os.urandom(KEY_LEN)
        salt = os.urandom(SALT_LEN)
        protector = _derive_key(password, salt, KDF_ITERATIONS_FAST)
        aead = AESGCM(protector)
        nonce = os.urandom(AES_NONCE_LEN)
        protected = aead.encrypt(nonce, master_key, b"master-key")
        final_blob = salt + nonce + protected

        # Попытка KSP, если запрошено
        if try_ksp:
            ok = try_store_to_windows_ksp("EncryptorMasterKey", master_key)
            if ok:
                # Запись небольшого файла-маркера с метаданными, ссылающимися на KSP
                meta = {"ksp_stored": True, "note": "Мастер-ключ сохранен в провайдере Windows KSP"}
                with open(out_path, "wb") as f:
                    f.write(base64.b64encode(json.dumps(meta).encode("utf-8")))
                return out_path

        if protect_with_dpapi and USE_DPAPI:
            try:
                final_blob = _dpapi_protect(final_blob)
            except Exception:
                # Возврат к незащищенному final_blob (все еще защищенному AES, выведенным из пароля)
                pass
        with open(out_path, "wb") as f:
            f.write(base64.b64encode(final_blob))
        return out_path

    def import_key(self, in_path: str, password: str) -> bytes:
        # Импорт мастер-ключа
        if not os.path.exists(in_path):
            raise ValueError("Файл не найден")
        b64 = open(in_path, "rb").read()
        # Проверка, содержит ли файл JSON-маркер для KSP
        try:
            maybe_json = base64.b64decode(b64)
            try:
                meta = json.loads(maybe_json.decode("utf-8"))
                if meta.get("ksp_stored"):
                    # Попытка извлечения
                    val = try_retrieve_from_windows_ksp("EncryptorMasterKey")
                    if val:
                        return val
                    else:
                        raise CryptoError("Найден маркер KSP, но извлечение не удалось")
            except Exception:
                # Не маркер, продолжаем обычный процесс
                pass
        except Exception:
            pass

        blob = base64.b64decode(b64)
        # Если защищено DPAPI, пытаемся расшифровать
        maybe = blob
        if USE_DPAPI:
            try:
                maybe_un = _dpapi_unprotect(blob)
                maybe = maybe_un
            except Exception:
                maybe = blob
        if len(maybe) < SALT_LEN + AES_NONCE_LEN + 16:
            raise CryptoError("Недопустимый формат экспортированного ключа")
        salt = maybe[:SALT_LEN]
        nonce = maybe[SALT_LEN:SALT_LEN + AES_NONCE_LEN]
        protected = maybe[SALT_LEN + AES_NONCE_LEN:]
        protector = _derive_key(password, salt, KDF_ITERATIONS_FAST)
        aead = AESGCM(protector)
        try:
            master_key = aead.decrypt(nonce, protected, b"master-key")
        except Exception as e:
            raise CryptoError("Не удается распаковать мастер-ключ (неверный пароль?)") from e
        return master_key