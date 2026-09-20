import flet as ft
import os
import zlib
import base64
import binascii

# ==================== مكتبات التشفير ====================
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization, hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from gmssl import sm4 as gmssl_sm4
    HAS_GMSSL = True
except ImportError:
    HAS_GMSSL = False

try:
    from Crypto.Cipher import (
        DES, DES3, Blowfish, CAST, ARC2, Salsa20, ARC4
    )
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


# ============================================================
#                    Plugins فك التشفير
# ============================================================
class BasePlugin:
    name = "Base"
    needs_key = True
    needs_iv = False
    needs_nonce = False
    description = ""

    def decrypt(self, data, key, iv, nonce):
        raise NotImplementedError


class XORPlugin(BasePlugin):
    name = "XOR"
    description = "XOR بمفتاح متكرر"

    def decrypt(self, data, key, iv, nonce):
        if not key:
            raise ValueError("المفتاح مطلوب")
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class ZlibPlugin(BasePlugin):
    name = "Zlib"
    needs_key = False
    description = "فك ضغط Zlib"

    def decrypt(self, data, key, iv, nonce):
        return zlib.decompress(data)


class ZstdPlugin(BasePlugin):
    name = "Zstd"
    needs_key = False
    description = "فك ضغط Zstandard"

    def decrypt(self, data, key, iv, nonce):
        if not HAS_ZSTD:
            raise RuntimeError("zstandard غير مثبتة")
        return zstd.ZstdDecompressor().decompress(data)


class Base64Plugin(BasePlugin):
    name = "Base64"
    needs_key = False
    description = "فك ترميز Base64"

    def decrypt(self, data, key, iv, nonce):
        return base64.b64decode(data)


class HexPlugin(BasePlugin):
    name = "Hex Decode"
    needs_key = False
    description = "فك ترميز Hex"

    def decrypt(self, data, key, iv, nonce):
        return binascii.unhexlify(data)


class AESGCMPlugin(BasePlugin):
    name = "AES-GCM"
    needs_nonce = True
    description = "AES بوضع GCM"

    def decrypt(self, data, key, iv, nonce):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography غير مثبتة")
        return AESGCM(key).decrypt(nonce, data, None)


class AESCBCPlugin(BasePlugin):
    name = "AES-CBC"
    needs_iv = True
    description = "AES بوضع CBC"

    def decrypt(self, data, key, iv, nonce):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography غير مثبتة")
        c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        d = c.decryptor()
        padded = d.update(data) + d.finalize()
        return padded[:-padded[-1]]


class AESCTRPlugin(BasePlugin):
    name = "AES-CTR"
    needs_nonce = True
    description = "AES بوضع CTR"

    def decrypt(self, data, key, iv, nonce):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography غير مثبتة")
        c = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        d = c.decryptor()
        return d.update(data) + d.finalize()


class AESCFBPlugin(BasePlugin):
    name = "AES-CFB"
    needs_iv = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography غير مثبتة")
        c = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        d = c.decryptor()
        return d.update(data) + d.finalize()


class AESOFBPlugin(BasePlugin):
    name = "AES-OFB"
    needs_iv = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography غير مثبتة")
        c = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
        d = c.decryptor()
        return d.update(data) + d.finalize()


class ChaCha20Plugin(BasePlugin):
    name = "ChaCha20-Poly1305"
    needs_nonce = True
    description = "ChaCha20 AEAD"

    def decrypt(self, data, key, iv, nonce):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography غير مثبتة")
        return ChaCha20Poly1305(key).decrypt(nonce, data, None)


class Salsa20Plugin(BasePlugin):
    name = "Salsa20"
    needs_nonce = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("pycryptodome غير مثبتة")
        return Salsa20.new(key=key, nonce=nonce).decrypt(data)


class DESCBCPlugin(BasePlugin):
    name = "DES-CBC"
    needs_iv = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("pycryptodome غير مثبتة")
        c = DES.new(key, DES.MODE_CBC, iv)
        padded = c.decrypt(data)
        return padded[:-padded[-1]]


class TripleDESPlugin(BasePlugin):
    name = "3DES-CBC"
    needs_iv = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("pycryptodome غير مثبتة")
        c = DES3.new(key, DES3.MODE_CBC, iv)
        padded = c.decrypt(data)
        return padded[:-padded[-1]]


class BlowfishPlugin(BasePlugin):
    name = "Blowfish-CBC"
    needs_iv = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("pycryptodome غير مثبتة")
        c = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded = c.decrypt(data)
        return padded[:-padded[-1]]


class CAST128Plugin(BasePlugin):
    name = "CAST-128-CBC"
    needs_iv = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("pycryptodome غير مثبتة")
        c = CAST.new(key, CAST.MODE_CBC, iv)
        padded = c.decrypt(data)
        return padded[:-padded[-1]]


class RC4Plugin(BasePlugin):
    name = "RC4"
    description = "RC4 Stream Cipher"

    def decrypt(self, data, key, iv, nonce):
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("pycryptodome غير مثبتة")
        return ARC4.new(key).decrypt(data)


class SM4ECBPlugin(BasePlugin):
    name = "SM4-ECB"

    def decrypt(self, data, key, iv, nonce):
        if not HAS_GMSSL:
            raise RuntimeError("gmssl غير مثبتة")
        c = gmssl_sm4.CryptSM4()
        c.set_key(key, gmssl_sm4.SM4_DECRYPT)
        return c.crypt_ecb(data)


class SM4CBCPlugin(BasePlugin):
    name = "SM4-CBC"
    needs_iv = True

    def decrypt(self, data, key, iv, nonce):
        if not HAS_GMSSL:
            raise RuntimeError("gmssl غير مثبتة")
        c = gmssl_sm4.CryptSM4()
        c.set_key(key, gmssl_sm4.SM4_DECRYPT)
        return c.crypt_cbc(iv, data)


class RSAOAIPPlugin(BasePlugin):
    name = "RSA-OAEP"
    needs_key = False
    description = "يحتاج ملف مفتاح خاص .pem"

    def __init__(self):
        self.private_key_path = None

    def decrypt(self, data, key, iv, nonce):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography غير مثبتة")
        if not self.private_key_path:
            raise ValueError("حدد ملف المفتاح الخاص")
        with open(self.private_key_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        return priv.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


def get_plugins():
    all_plugins = [
        AESGCMPlugin(), AESCBCPlugin(), AESCTRPlugin(),
        AESCFBPlugin(), AESOFBPlugin(),
        ChaCha20Plugin(), Salsa20Plugin(),
        DESCBCPlugin(), TripleDESPlugin(), BlowfishPlugin(),
        CAST128Plugin(), RC4Plugin(),
        SM4ECBPlugin(), SM4CBCPlugin(),
        RSAOAIPPlugin(),
        XORPlugin(),
        ZlibPlugin(), ZstdPlugin(),
        Base64Plugin(), HexPlugin(),
    ]
    return {p.name: p for p in all_plugins}


# ============================================================
#                    واجهة Flet الفخمة
# ============================================================
def main(page: ft.Page):
    page.title = "Decryptor Pro"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.bgcolor = "#0A0E1A"
    page.scroll = ft.ScrollMode.AUTO
    page.fonts = {
        "Cairo": "https://github.com/google/fonts/raw/main/ofl/cairo/Cairo%5Bslnt%2Cwght%5D.ttf"
    }
    page.theme = ft.Theme(font_family="Cairo")

    BG = "#0A0E1A"
    CARD = "#131826"
    CARD2 = "#1A2033"
    ACCENT = "#6366F1"
    ACCENT2 = "#8B5CF6"
    SUCCESS = "#10B981"
    DANGER = "#EF4444"
    TEXT = "#E8EAED"
    TEXT_DIM = "#9AA0AA"

    plugins = get_plugins()

    state = {
        "file_path": None,
        "file_name": "لم يتم اختيار ملف",
        "rsa_path": None,
    }

    file_name_label = ft.Text(
        "لم يتم اختيار ملف", size=13, color=TEXT_DIM, text_align=ft.TextAlign.CENTER
    )
    file_size_label = ft.Text("", size=11, color=TEXT_DIM)

    algo_dropdown = ft.Dropdown(
        label="الخوارزمية",
        value="AES-GCM",
        options=[ft.dropdown.Option(name) for name in plugins.keys()],
        bgcolor=CARD2,
        border_color=ACCENT,
        color=TEXT,
        label_style=ft.TextStyle(color=TEXT_DIM),
        text_style=ft.TextStyle(color=TEXT, size=14),
        border_radius=12,
        filled=True,
    )

    key_field = ft.TextField(
        label="المفتاح (HEX أو نص)",
        password=True,
        can_reveal_password=True,
        bgcolor=CARD2,
        border_color=ACCENT,
        color=TEXT,
        label_style=ft.TextStyle(color=TEXT_DIM),
        text_style=ft.TextStyle(color=TEXT, size=14, font_family="monospace"),
        border_radius=12,
        filled=True,
    )

    iv_field = ft.TextField(
        label="IV (HEX أو نص)",
        bgcolor=CARD2,
        border_color=ACCENT,
        color=TEXT,
        label_style=ft.TextStyle(color=TEXT_DIM),
        text_style=ft.TextStyle(color=TEXT, size=14, font_family="monospace"),
        border_radius=12,
        filled=True,
    )

    nonce_field = ft.TextField(
        label="Nonce (HEX)",
        bgcolor=CARD2,
        border_color=ACCENT,
        color=TEXT,
        label_style=ft.TextStyle(color=TEXT_DIM),
        text_style=ft.TextStyle(color=TEXT, size=14, font_family="monospace"),
        border_radius=12,
        filled=True,
    )

    hex_switch = ft.Switch(
        label="المفاتيح بصيغة HEX",
        value=True,
        active_color=ACCENT,
        label_style=ft.TextStyle(color=TEXT_DIM, size=12),
    )

    log_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, height=180)

    progress = ft.ProgressBar(
        width=400, color=ACCENT, bgcolor=CARD2, visible=False, border_radius=8
    )

    rsa_label = ft.Text("", size=11, color=SUCCESS)

    def parse_input(s, is_hex):
        if not s:
            return b""
        if is_hex:
            try:
                return bytes.fromhex(s.replace(" ", "").replace("\n", ""))
            except ValueError:
                return s.encode()
        return s.encode()

    def log(msg, color=SUCCESS):
        log_list.controls.append(
            ft.Container(
                content=ft.Text(msg, color=color, size=12, selectable=True),
                padding=ft.padding.symmetric(horizontal=10, vertical=6),
                bgcolor=CARD2,
                border_radius=8,
            )
        )
        page.update()

    def clear_log(e=None):
        log_list.controls.clear()
        page.update()

    def on_file_picked(e: ft.FilePickerResultEvent):
        if e.files and len(e.files) > 0:
            f = e.files[0]
            state["file_path"] = f.path
            state["file_name"] = f.name
            file_name_label.value = f.name
            file_name_label.color = TEXT
            size_kb = (f.size or 0) / 1024
            file_size_label.value = f"{size_kb:.1f} KB"
            page.update()
            log(f"تم اختيار: {f.name}")

    file_picker = ft.FilePicker(on_result=on_file_picked)

    def pick_file(e):
        file_picker.pick_files(allow_multiple=False, dialog_title="اختر الملف")

    def on_rsa_picked(e: ft.FilePickerResultEvent):
        if e.files and len(e.files) > 0:
            state["rsa_path"] = e.files[0].path
            rsa_label.value = f"تم تحميل: {e.files[0].name}"
            page.update()

    rsa_picker = ft.FilePicker(on_result=on_rsa_picked)

    def pick_rsa(e):
        rsa_picker.pick_files(
            allow_multiple=False,
            allowed_extensions=["pem", "key"],
            dialog_title="اختر المفتاح الخاص",
        )

    def run_decrypt(e):
        if not state["file_path"] or not os.path.isfile(state["file_path"]):
            log("اختر ملف أولاً", DANGER)
            return

        plugin = plugins.get(algo_dropdown.value)
        if not plugin:
            log("خوارزمية غير معروفة", DANGER)
            return

        if isinstance(plugin, RSAOAIPPlugin):
            plugin.private_key_path = state["rsa_path"]

        try:
            progress.visible = True
            page.update()

            key = parse_input(key_field.value, hex_switch.value)
            iv = parse_input(iv_field.value, hex_switch.value)
            nonce = parse_input(nonce_field.value, hex_switch.value)

            with open(state["file_path"], "rb") as f:
                data = f.read()

            log(f"جاري فك التشفير بـ {plugin.name} ({len(data)} بايت)...", "#F59E0B")
            result = plugin.decrypt(data, key, iv, nonce)

            out_path = state["file_path"] + ".decrypted"
            with open(out_path, "wb") as f:
                f.write(result)

            log(f"تم الحفظ: {os.path.basename(out_path)} ({len(result)} بايت)")
            page.snack_bar = ft.SnackBar(
                content=ft.Text("تم فك التشفير بنجاح", color="white"),
                bgcolor=SUCCESS,
            )
            page.snack_bar.open = True

        except Exception as ex:
            log(f"{type(ex).__name__}: {ex}", DANGER)
            page.snack_bar = ft.SnackBar(
                content=ft.Text(f"خطأ: {ex}", color="white"),
                bgcolor=DANGER,
            )
            page.snack_bar.open = True
        finally:
            progress.visible = False
            page.update()

    def preview(e):
        if not state["file_path"] or not os.path.isfile(state["file_path"]):
            log("اختر ملف أولاً", DANGER)
            return
        with open(state["file_path"], "rb") as f:
            head = f.read(32)
        hex_str = " ".join(f"{b:02X}" for b in head)
        log(f"أول 32 بايت:\n{hex_str}", "#22D3EE")

    header = ft.Container(
        content=ft.Column([
            ft.Container(height=20),
            ft.Row([
                ft.Container(
                    content=ft.Icon(ft.icons.LOCK_PERSON, size=32, color="white"),
                    width=64, height=64,
                    bgcolor=ACCENT,
                    border_radius=20,
                    alignment=ft.alignment.center,
                ),
            ], alignment=ft.MainAxisAlignment.CENTER),
            ft.Container(height=12),
            ft.Text("Decryptor Pro", size=26, weight=ft.FontWeight.BOLD,
                    color=TEXT, text_align=ft.TextAlign.CENTER),
            ft.Text("فك تشفير ملفاتك باحترافية وأمان", size=12,
                    color=TEXT_DIM, text_align=ft.TextAlign.CENTER),
            ft.Container(height=20),
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        gradient=ft.LinearGradient(
            begin=ft.alignment.top_center,
            end=ft.alignment.bottom_center,
            colors=["#1E1B4B", BG],
        ),
        padding=ft.padding.symmetric(horizontal=20),
    )

    file_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Icon(ft.icons.FOLDER_OPEN, color=ACCENT, size=20),
                ft.Text("الملف المشفر", weight=ft.FontWeight.BOLD, color=TEXT, size=15),
            ], alignment=ft.MainAxisAlignment.START),
            ft.Container(
                content=ft.Column([
                    ft.Icon(ft.icons.UPLOAD_FILE, size=40, color=ACCENT),
                    file_name_label,
                    file_size_label,
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
                padding=20,
                bgcolor=CARD2,
                border_radius=12,
                border=ft.border.all(1, "#2A2F3A"),
                on_click=pick_file,
                ink=True,
            ),
        ], spacing=10),
        padding=16,
        bgcolor=CARD,
        border_radius=16,
        margin=ft.margin.symmetric(horizontal=16, vertical=6),
    )

    settings_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Icon(ft.icons.SETTINGS, color=ACCENT2, size=20),
                ft.Text("إعدادات فك التشفير", weight=ft.FontWeight.BOLD, color=TEXT, size=15),
            ]),
            algo_dropdown,
            key_field,
            iv_field,
            nonce_field,
            ft.Row([
                hex_switch,
                ft.TextButton(
                    "مفتاح RSA",
                    on_click=pick_rsa,
                    style=ft.ButtonStyle(color=ACCENT2),
                ),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            rsa_label,
        ], spacing=10),
        padding=16,
        bgcolor=CARD,
        border_radius=16,
        margin=ft.margin.symmetric(horizontal=16, vertical=6),
    )

    action_buttons = ft.Container(
        content=ft.Column([
            ft.ElevatedButton(
                content=ft.Row([
                    ft.Icon(ft.icons.LOCK_OPEN, color="white", size=22),
                    ft.Text("فك التشفير", color="white", size=16, weight=ft.FontWeight.BOLD),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=10),
                on_click=run_decrypt,
                style=ft.ButtonStyle(
                    bgcolor=ACCENT,
                    shape=ft.RoundedRectangleBorder(radius=14),
                    padding=ft.padding.symmetric(vertical=18),
                ),
                width=400,
            ),
            ft.OutlinedButton(
                content=ft.Row([
                    ft.Icon(ft.icons.VISIBILITY, color=ACCENT2, size=20),
                    ft.Text("معاينة البايتات", color=ACCENT2, size=14),
                ], alignment=ft.MainAxisAlignment.CENTER),
                on_click=preview,
                style=ft.ButtonStyle(
                    shape=ft.RoundedRectangleBorder(radius=14),
                    side=ft.BorderSide(1.5, ACCENT2),
                    padding=ft.padding.symmetric(vertical=14),
                ),
                width=400,
            ),
            progress,
        ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=12),
        margin=ft.margin.symmetric(horizontal=16, vertical=6),
    )

    log_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Icon(ft.icons.TERMINAL, color=SUCCESS, size=20),
                ft.Text("السجل", weight=ft.FontWeight.BOLD, color=TEXT, size=15),
                ft.Container(expand=True),
                ft.IconButton(
                    icon=ft.icons.DELETE_OUTLINE,
                    icon_color=TEXT_DIM,
                    icon_size=18,
                    on_click=clear_log,
                ),
            ]),
            log_list,
        ], spacing=10),
        padding=16,
        bgcolor=CARD,
        border_radius=16,
        margin=ft.margin.symmetric(horizontal=16, vertical=6),
    )

    footer = ft.Container(
        content=ft.Text("جميع العمليات تتم على جهازك", size=11,
                        color=TEXT_DIM, text_align=ft.TextAlign.CENTER),
        padding=20,
    )

    page.overlay.append(file_picker)
    page.overlay.append(rsa_picker)
    page.add(
        header,
        file_card,
        settings_card,
        action_buttons,
        log_card,
        footer,
    )
    log("أهلاً بك في Decryptor Pro", ACCENT2)


if __name__ == "__main__":
    ft.run(main)