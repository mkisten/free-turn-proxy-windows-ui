import ctypes
import csv
from datetime import datetime
import io
import json
import os
import queue
import re
import subprocess
import threading
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


CLIENT_URL = (
    "https://github.com/samosvalishe/free-turn-proxy/releases/latest/download/"
    "client-windows-amd64.exe"
)
ROUTES_URL = (
    "https://raw.githubusercontent.com/samosvalishe/free-turn-proxy/master/scripts/routes.ps1"
)
BUNDLED_DIR = Path(__file__).resolve().parent
LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA", Path.home()))
DATA_DIR = LOCAL_APPDATA / "FreeTurnProxyWindowsClient"
LOGS_DIR = DATA_DIR / "logs"
CONFIG_PATH = DATA_DIR / "settings.json"
DEFAULT_CLIENT_PATH = DATA_DIR / "client.exe"
DEFAULT_ROUTES_PATH = DATA_DIR / "routes.ps1"
DEFAULT_GENERATED_CONFIG_PATH = DATA_DIR / "freeturn-wg.conf"
DEFAULT_WIREGUARD_PATH = Path(r"C:\Program Files\WireGuard\wireguard.exe")


DEFAULT_SETTINGS = {
    "peer": "",
    "listen": "127.0.0.1:9000",
    "provider": "vk",
    "link": "",
    "obf_profile": "",
    "obf_key": "",
    "dns_servers": "",
    "streams": "2",
    "manual_captcha": False,
    "debug": True,
    "use_routes": True,
    "client_path": str(DEFAULT_CLIENT_PATH),
    "routes_path": str(DEFAULT_ROUTES_PATH),
    "wireguard_path": str(DEFAULT_WIREGUARD_PATH),
    "tunnel_name": "freeturn-wg",
    "generated_config_path": str(DEFAULT_GENERATED_CONFIG_PATH),
    "wg_config": "",
}

CONFLICTING_PROCESS_HINTS = {
    "clash-verge.exe": "Clash Verge",
    "clash.exe": "Clash",
    "openvpn.exe": "OpenVPN",
    "openvpn-gui.exe": "OpenVPN GUI",
    "openvpnserv.exe": "OpenVPN Service",
    "openvpnserv2.exe": "OpenVPN Service 2",
    "warp-svc.exe": "Cloudflare WARP",
    "cloudflare-warp.exe": "Cloudflare WARP",
    "proxifier.exe": "Proxifier",
    "adguard.exe": "AdGuard",
}


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sanitize_filename(value):
    cleaned = re.sub(r'[<>:"/\\|?*]+', "-", value.strip())
    return cleaned or "freeturn-wg"


def normalize_config_line(value):
    return value.replace("\ufeff", "").replace("\u200b", "").replace("\u200e", "").replace("\u200f", "")


def collapse_exact_double(value):
    text = (value or "").strip()
    if not text or len(text) % 2 != 0:
        return text
    half = len(text) // 2
    if text[:half] == text[half:]:
        return text[:half]
    return text


def expand_default_allowed_ips(value):
    text = value.strip()
    if not text:
        return text
    parts = [part.strip() for part in text.split(",") if part.strip()]
    expanded = []
    for part in parts:
        if part == "0.0.0.0/0":
            expanded.extend(["0.0.0.0/1", "128.0.0.0/1"])
        elif part == "::/0":
            expanded.extend(["::/1", "8000::/1"])
        else:
            expanded.append(part)
    return ", ".join(expanded)


def detect_conflicting_processes():
    try:
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except Exception:
        return []

    found = []
    reader = csv.reader(io.StringIO(result.stdout))
    for row in reader:
        if not row:
            continue
        image_name = row[0].strip().lower()
        if image_name in CONFLICTING_PROCESS_HINTS:
            found.append(CONFLICTING_PROCESS_HINTS[image_name])
    return sorted(set(found))


class FreeTurnProxyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

        self.title("Free Turn Proxy Windows Client")
        self.geometry("1080x980")
        self.minsize(980, 860)

        self.output_queue = queue.Queue()
        self.client_process = None
        self.routes_process = None
        self.worker_threads = []
        self.link_entry = None
        self.wg_text = None
        self.routes_ready = False
        self.dtls_ready = False
        self.dtls_ready_at = None
        self.pending_connect_all = False
        self.wg_info_var = tk.StringVar(
            value="Приложение автоматически заменит Endpoint на локальный listen."
        )
        self.vpn_status_var = tk.StringVar(value="VPN: неизвестно")
        self.log_file_path = LOGS_DIR / f"session-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"

        self.vars = {}
        self.status_var = tk.StringVar(value="Отключено")
        self.admin_var = tk.StringVar(
            value="Права администратора: есть" if is_admin() else "Права администратора: нет"
        )
        self.data_dir_var = tk.StringVar(value=f"Папка данных: {DATA_DIR}")
        self.log_file_var = tk.StringVar(value=f"Лог: {self.log_file_path}")

        self._create_variables()
        self._build_ui()
        self._bind_shortcuts()
        self.load_settings()
        self.after(100, self._drain_output_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _create_variables(self):
        self.vars["peer"] = tk.StringVar()
        self.vars["listen"] = tk.StringVar()
        self.vars["provider"] = tk.StringVar()
        self.vars["link"] = tk.StringVar()
        self.vars["obf_profile"] = tk.StringVar()
        self.vars["obf_key"] = tk.StringVar()
        self.vars["dns_servers"] = tk.StringVar()
        self.vars["streams"] = tk.StringVar()
        self.vars["manual_captcha"] = tk.BooleanVar()
        self.vars["debug"] = tk.BooleanVar()
        self.vars["use_routes"] = tk.BooleanVar()
        self.vars["client_path"] = tk.StringVar()
        self.vars["routes_path"] = tk.StringVar()
        self.vars["wireguard_path"] = tk.StringVar()
        self.vars["tunnel_name"] = tk.StringVar()
        self.vars["generated_config_path"] = tk.StringVar()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.rowconfigure(3, weight=1)

        header = ttk.Frame(self, padding=12)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(
            header,
            text="Free Turn Proxy для Windows",
            font=("Segoe UI", 18, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(header, textvariable=self.status_var).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Label(header, textvariable=self.admin_var).grid(row=2, column=0, sticky="w", pady=(4, 0))
        ttk.Label(header, textvariable=self.data_dir_var).grid(row=3, column=0, sticky="w", pady=(4, 0))
        ttk.Label(header, textvariable=self.log_file_var).grid(row=4, column=0, sticky="w", pady=(4, 0))

        form = ttk.Frame(self, padding=(12, 0, 12, 12))
        form.grid(row=1, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        self._add_entry(form, 0, "Путь к client.exe", "client_path", browse_mode="open")
        self._add_action_button(form, 0, 4, "Скачать client.exe", self.download_client)

        self._add_entry(form, 1, "Путь к routes.ps1", "routes_path", browse_mode="open")
        self._add_action_button(form, 1, 4, "Скачать routes.ps1", self.download_routes)

        self._add_entry(form, 2, "Путь к wireguard.exe", "wireguard_path", browse_mode="open")

        self._add_entry(form, 3, "Сервер", "peer")
        self._add_entry(form, 3, "Локальный listen", "listen", column=2)

        self._add_entry(form, 4, "Provider", "provider")
        self._add_entry(form, 4, "Потоки (-n)", "streams", column=2)

        self._add_entry(form, 5, "Профиль obf", "obf_profile")
        self._add_entry(form, 5, "Ключ obf", "obf_key", column=2, show="*")

        self._add_entry(form, 6, "Имя туннеля", "tunnel_name")
        self._add_entry(form, 6, "Куда сохранить .conf", "generated_config_path", column=2, browse_mode="save")

        self._add_entry(form, 7, "DNS servers", "dns_servers")

        ttk.Label(form, text="VK Calls ссылка").grid(row=8, column=0, sticky="w", padx=(0, 8), pady=(10, 4))
        link_row = ttk.Frame(form)
        link_row.grid(row=9, column=0, columnspan=5, sticky="ew", pady=(0, 10))
        link_row.columnconfigure(0, weight=1)
        self.link_entry = ttk.Entry(link_row, textvariable=self.vars["link"])
        self.link_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(link_row, text="Вставить", command=self.paste_link).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(link_row, text="Очистить", command=lambda: self.vars["link"].set("")).grid(row=0, column=2)

        options = ttk.Frame(form)
        options.grid(row=10, column=0, columnspan=5, sticky="w", pady=(0, 12))
        ttk.Checkbutton(options, text="Использовать routes.ps1", variable=self.vars["use_routes"]).grid(
            row=0, column=0, sticky="w", padx=(0, 16)
        )
        ttk.Checkbutton(options, text="Ручная captcha", variable=self.vars["manual_captcha"]).grid(
            row=0, column=1, sticky="w", padx=(0, 16)
        )
        ttk.Checkbutton(options, text="Debug лог", variable=self.vars["debug"]).grid(
            row=0, column=2, sticky="w"
        )

        buttons = ttk.Frame(form)
        buttons.grid(row=11, column=0, columnspan=5, sticky="w")
        ttk.Button(buttons, text="Сохранить настройки", command=self.save_settings).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(buttons, text="Сохранить локальный .conf", command=self.save_generated_config).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(buttons, text="Скопировать локальный .conf", command=self.copy_generated_config).grid(
            row=0, column=2, padx=(0, 8)
        )
        self.start_button = ttk.Button(buttons, text="Подключить", command=self.start_connection)
        self.start_button.grid(row=0, column=3, padx=(0, 8))
        self.stop_button = ttk.Button(buttons, text="Отключить", command=self.stop_connection, state="disabled")
        self.stop_button.grid(row=0, column=4)
        ttk.Button(buttons, text="Открыть папку логов", command=self.open_logs_dir).grid(
            row=0, column=5, padx=(8, 0)
        )

        vpn_buttons = ttk.Frame(form)
        vpn_buttons.grid(row=12, column=0, columnspan=5, sticky="w", pady=(10, 0))
        ttk.Button(vpn_buttons, text="Установить туннель", command=self.install_vpn_tunnel).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(vpn_buttons, text="Подключить VPN", command=self.connect_vpn).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(vpn_buttons, text="Отключить VPN", command=self.disconnect_vpn).grid(
            row=0, column=2, padx=(0, 8)
        )
        ttk.Button(vpn_buttons, text="Подключить все", command=self.connect_all).grid(
            row=0, column=3, padx=(0, 8)
        )
        ttk.Button(vpn_buttons, text="Статус VPN", command=self.refresh_vpn_status).grid(
            row=0, column=4
        )
        ttk.Label(form, textvariable=self.vpn_status_var).grid(row=13, column=0, columnspan=5, sticky="w", pady=(8, 0))

        wg_frame = ttk.Frame(self, padding=(12, 0, 12, 12))
        wg_frame.grid(row=2, column=0, sticky="nsew")
        wg_frame.columnconfigure(0, weight=1)
        wg_frame.rowconfigure(2, weight=1)

        ttk.Label(wg_frame, text="Конфигурация WireGuard (.conf)").grid(row=0, column=0, sticky="w")
        wg_buttons = ttk.Frame(wg_frame)
        wg_buttons.grid(row=0, column=1, sticky="e")
        ttk.Button(wg_buttons, text="Открыть .conf", command=self.load_wireguard_file).grid(
            row=0, column=0, padx=(0, 8)
        )
        ttk.Button(wg_buttons, text="Вставить", command=self.paste_wireguard_config).grid(
            row=0, column=1, padx=(0, 8)
        )
        ttk.Button(wg_buttons, text="Очистить", command=self.clear_wireguard_config).grid(row=0, column=2)

        ttk.Label(wg_frame, textvariable=self.wg_info_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 6))

        self.wg_text = tk.Text(wg_frame, wrap="word", font=("Cascadia Mono", 10), height=14)
        self.wg_text.grid(row=2, column=0, columnspan=2, sticky="nsew")
        wg_scroll = ttk.Scrollbar(wg_frame, orient="vertical", command=self.wg_text.yview)
        wg_scroll.grid(row=2, column=2, sticky="ns")
        self.wg_text.configure(yscrollcommand=wg_scroll.set)

        log_frame = ttk.Frame(self, padding=(12, 0, 12, 12))
        log_frame.grid(row=3, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)

        ttk.Label(log_frame, text="Лог").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.log_text = tk.Text(log_frame, wrap="word", state="disabled", font=("Cascadia Mono", 10))
        self.log_text.grid(row=1, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=1, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

    def _add_entry(self, parent, row, label, key, column=0, browse_mode=None, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=column, sticky="w", padx=(0, 8), pady=(0, 6))
        entry = ttk.Entry(parent, textvariable=self.vars[key], show=show)
        entry.grid(row=row, column=column + 1, sticky="ew", padx=(0, 12), pady=(0, 6))
        parent.columnconfigure(column + 1, weight=1)
        if browse_mode is not None:
            ttk.Button(
                parent,
                text="Обзор",
                command=lambda current=key, mode=browse_mode: self.browse_path(current, mode),
            ).grid(row=row, column=column + 2, padx=(0, 12), pady=(0, 6))

    def _add_action_button(self, parent, row, column, text, command):
        ttk.Button(parent, text=text, command=command).grid(row=row, column=column, sticky="ew", pady=(0, 6))

    def _bind_shortcuts(self):
        self.bind_all("<Control-v>", self._paste_into_focused_widget, add="+")
        self.bind_all("<Control-V>", self._paste_into_focused_widget, add="+")
        self.bind_all("<Shift-Insert>", self._paste_into_focused_widget, add="+")

    def browse_path(self, key, mode):
        initial_dir = DATA_DIR if DATA_DIR.exists() else BUNDLED_DIR
        if mode == "save":
            path = filedialog.asksaveasfilename(
                initialdir=initial_dir,
                initialfile=f"{sanitize_filename(self.vars['tunnel_name'].get())}.conf",
                defaultextension=".conf",
                filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")],
            )
        else:
            path = filedialog.askopenfilename(initialdir=initial_dir)
        if path:
            self.vars[key].set(path)

    def paste_link(self):
        try:
            text = self.clipboard_get()
        except Exception as exc:
            messagebox.showerror("Буфер обмена", f"Не удалось прочитать буфер обмена: {exc}")
            return
        self.vars["link"].set(text)
        if self.link_entry is not None:
            self.link_entry.focus_set()
            self.link_entry.icursor("end")

    def paste_wireguard_config(self):
        try:
            text = self.clipboard_get()
        except Exception as exc:
            messagebox.showerror("Буфер обмена", f"Не удалось прочитать буфер обмена: {exc}")
            return
        self._set_wg_config_text(text)
        self._append_log("app", "WireGuard-конфиг вставлен из буфера обмена.")

    def clear_wireguard_config(self):
        self._set_wg_config_text("")

    def load_wireguard_file(self):
        path = filedialog.askopenfilename(
            initialdir=DATA_DIR if DATA_DIR.exists() else BUNDLED_DIR,
            filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            text = Path(path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = Path(path).read_text(encoding="utf-8-sig")
        except Exception as exc:
            messagebox.showerror("Чтение файла", f"Не удалось открыть {path}: {exc}")
            return

        self._set_wg_config_text(text)
        current_generated = Path(self.vars["generated_config_path"].get() or DEFAULT_GENERATED_CONFIG_PATH)
        if current_generated == DEFAULT_GENERATED_CONFIG_PATH or not current_generated.exists():
            stem = sanitize_filename(Path(path).stem)
            self.vars["tunnel_name"].set(stem)
            self.vars["generated_config_path"].set(str(DATA_DIR / f"{stem}.conf"))
        self._append_log("app", f"Загружен WireGuard-конфиг: {path}")

    def _paste_into_focused_widget(self, _event=None):
        widget = self.focus_get()
        if widget is None:
            return
        try:
            text = self.clipboard_get()
        except Exception:
            return

        try:
            widget.insert("insert", text)
        except Exception:
            return "break"
        return "break"

    def _get_wg_config_text(self):
        if self.wg_text is None:
            return ""
        return self.wg_text.get("1.0", "end").strip()

    def _set_wg_config_text(self, value):
        if self.wg_text is None:
            return
        self.wg_text.delete("1.0", "end")
        self.wg_text.insert("1.0", value)

    def _normalize_generated_config_path(self):
        current = self.vars["generated_config_path"].get().strip()
        if current:
            return Path(current)
        tunnel_name = sanitize_filename(self.vars["tunnel_name"].get())
        path = DATA_DIR / f"{tunnel_name}.conf"
        self.vars["generated_config_path"].set(str(path))
        return path

    def _get_tunnel_stem(self):
        configured = self.vars["generated_config_path"].get().strip()
        if configured:
            stem = sanitize_filename(Path(configured).stem)
            if stem:
                return stem
        return sanitize_filename(self.vars["tunnel_name"].get())

    def _patch_wireguard_config(self, config_text):
        text = config_text.replace("\r\n", "\n").replace("\r", "\n").strip()
        if not text:
            raise ValueError("WireGuard-конфиг пустой.")

        listen = self.vars["listen"].get().strip()
        if not listen:
            raise ValueError("Локальный listen пустой.")

        loopback_host = listen.split(":")[0].strip()
        should_expand_default_allowed_ips = loopback_host in {"127.0.0.1", "localhost"}

        lines = [normalize_config_line(line) for line in text.split("\n")]
        endpoint_replaced = False
        in_peer = False
        first_peer_index = None
        peer_insert_index = None
        inferred_peer_index = None
        patched_lines = []
        peer_key_re = re.compile(
            r"^\s*(PublicKey|PresharedKey|AllowedIPs|PersistentKeepalive|Endpoint)\s*=",
            re.IGNORECASE,
        )
        section_re = re.compile(r"^\[\s*([^\]]+?)\s*\]$", re.IGNORECASE)

        for index, line in enumerate(lines):
            stripped = line.strip()
            section_match = section_re.match(stripped)
            if section_match:
                if in_peer and peer_insert_index is None:
                    peer_insert_index = index
                in_peer = section_match.group(1).strip().lower() == "peer"
                if in_peer and first_peer_index is None:
                    first_peer_index = index

            if (
                inferred_peer_index is None
                and first_peer_index is None
                and not section_match
                and peer_key_re.match(stripped)
            ):
                inferred_peer_index = index

            if not stripped.startswith("#") and re.match(r"^\s*Endpoint\s*=", stripped, re.IGNORECASE):
                leading = re.match(r"^(\s*)", line).group(1)
                patched_lines.append(f"{leading}Endpoint = {listen}")
                endpoint_replaced = True
                continue

            if (
                should_expand_default_allowed_ips
                and not stripped.startswith("#")
                and re.match(r"^\s*AllowedIPs\s*=", stripped, re.IGNORECASE)
            ):
                leading = re.match(r"^(\s*)", line).group(1)
                _, raw_value = line.split("=", 1)
                patched_lines.append(f"{leading}AllowedIPs = {expand_default_allowed_ips(raw_value)}")
                continue

            patched_lines.append(line)

        if endpoint_replaced:
            return "\n".join(patched_lines).strip() + "\n"

        if first_peer_index is None and inferred_peer_index is not None:
            patched_lines.insert(inferred_peer_index, "[Peer]")
            patched_lines.insert(inferred_peer_index + 1, f"Endpoint = {listen}")
            return "\n".join(patched_lines).strip() + "\n"

        if first_peer_index is None:
            raise ValueError("В конфиге нет секции [Peer], некуда подставить Endpoint.")

        insert_at = peer_insert_index if peer_insert_index is not None else len(patched_lines)
        patched_lines.insert(insert_at, f"Endpoint = {listen}")
        return "\n".join(patched_lines).strip() + "\n"

    def _generate_wireguard_config(self):
        return self._patch_wireguard_config(self._get_wg_config_text())

    def load_settings(self):
        settings = dict(DEFAULT_SETTINGS)
        if CONFIG_PATH.exists():
            try:
                settings.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
            except Exception as exc:
                self._append_log("app", f"Не удалось прочитать settings.json: {exc}")

        wg_config = settings.pop("wg_config", "")
        settings["obf_key"] = collapse_exact_double(str(settings.get("obf_key", "")))
        settings["tunnel_name"] = collapse_exact_double(str(settings.get("tunnel_name", "")))
        settings["dns_servers"] = collapse_exact_double(str(settings.get("dns_servers", "")))
        for key, value in settings.items():
            self.vars[key].set(value)
        self._set_wg_config_text(wg_config)
        self.after(200, self.refresh_vpn_status)

    def save_settings(self):
        data = {}
        for key, variable in self.vars.items():
            value = variable.get()
            if key in {"obf_key", "tunnel_name", "dns_servers"}:
                value = collapse_exact_double(str(value))
                variable.set(value)
            data[key] = value
        data["wg_config"] = self._get_wg_config_text()
        CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self._append_log("app", f"Настройки сохранены в {CONFIG_PATH}")

    def download_client(self):
        self._download_file(CLIENT_URL, Path(self.vars["client_path"].get()), "client.exe")

    def download_routes(self):
        self._download_file(ROUTES_URL, Path(self.vars["routes_path"].get()), "routes.ps1")

    def _download_file(self, url, target_path, label):
        def worker():
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                self.output_queue.put(("app", f"Скачиваю {label}..."))
                urllib.request.urlretrieve(url, str(target_path))
                self.output_queue.put(("app", f"{label} сохранен: {target_path}"))
            except Exception as exc:
                self.output_queue.put(("app", f"Ошибка скачивания {label}: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def save_generated_config(self, show_message=True):
        try:
            generated = self._generate_wireguard_config()
            output_path = self._normalize_generated_config_path()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(generated, encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("WireGuard", str(exc))
            return None

        self._append_log("app", f"Локальный WireGuard-конфиг сохранен: {output_path}")
        if show_message:
            messagebox.showinfo("WireGuard", f"Конфиг сохранен:\n{output_path}")
        return output_path

    def _is_routes_ready_line(self, message):
        normalized = message.strip().lower()
        return (
            normalized.startswith("ensuring route to ")
            or normalized.startswith("route to ")
            or normalized.startswith("updating route to ")
        )

    def _get_wireguard_path(self):
        configured = self.vars["wireguard_path"].get().strip()
        path = Path(configured) if configured else DEFAULT_WIREGUARD_PATH
        if not path.exists():
            raise FileNotFoundError(f"wireguard.exe не найден: {path}")
        return path

    def _get_service_name(self):
        return f"WireGuardTunnel${self._get_tunnel_stem()}"

    def _ensure_admin_for_vpn_action(self, action_label):
        if is_admin():
            return True
        messagebox.showerror(
            "Нужны права администратора",
            (
                f"Для действия '{action_label}' нужны права администратора.\n\n"
                "Запустите приложение от имени администратора и повторите попытку."
            ),
        )
        return False

    def _stop_tunnel_service_if_needed(self):
        status = self._get_service_status()
        if status not in {"Running", "StartPending"}:
            return
        service_name = self._get_service_name()
        result = self._run_process(
            ["powershell", "-NoProfile", "-Command", f"Stop-Service -Name '{service_name}' -Force"],
            "vpn",
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Не удалось остановить сервис туннеля.")

    def _start_tunnel_service(self):
        service_name = self._get_service_name()
        result = self._run_process(
            ["powershell", "-NoProfile", "-Command", f"Start-Service -Name '{service_name}'"],
            "vpn",
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Не удалось запустить сервис туннеля.")

    def _reinstall_tunnel_service(self, config_path):
        status = self._get_service_status()
        tunnel_name = self._get_tunnel_stem()
        if status != "NOT_INSTALLED":
            self._stop_tunnel_service_if_needed()
            self._run_wireguard_command(["/uninstalltunnelservice", tunnel_name], "vpn")
        self._run_wireguard_command(["/installtunnelservice", str(config_path)], "vpn")

    def _ensure_tunnel_service_ready(self, config_path):
        status = self._get_service_status()
        if status == "NOT_INSTALLED":
            self._reinstall_tunnel_service(config_path)
            return
        if status == "Stopped":
            self._start_tunnel_service()
            return
        if status in {"Running", "StartPending"}:
            return
        self._reinstall_tunnel_service(config_path)

    def _run_process(self, command, label):
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
        if output:
            self._append_log(label, output)
        return result

    def _run_wireguard_command(self, args, label):
        wireguard_path = self._get_wireguard_path()
        result = self._run_process([str(wireguard_path)] + args, label)
        if result.returncode != 0:
            raise RuntimeError(
                output if (output := "\n".join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip()))
                else f"Команда WireGuard завершилась с кодом {result.returncode}."
            )
        return result

    def _get_service_status(self):
        service_name = self._get_service_name().replace("'", "''")
        result = self._run_process(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"$svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue; "
                    "if ($null -eq $svc) { Write-Output 'NOT_INSTALLED' } else { Write-Output $svc.Status }"
                ),
            ],
            "vpn",
        )
        status = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
        return status or "UNKNOWN"

    def refresh_vpn_status(self):
        try:
            status = self._get_service_status()
        except Exception as exc:
            self.vpn_status_var.set(f"VPN: ошибка статуса ({exc})")
            return

        mapping = {
            "NOT_INSTALLED": "VPN: туннель не установлен",
            "Running": "VPN: подключен",
            "Stopped": "VPN: установлен, но отключен",
            "StartPending": "VPN: подключается",
            "StopPending": "VPN: отключается",
        }
        self.vpn_status_var.set(mapping.get(status, f"VPN: {status}"))

    def install_vpn_tunnel(self):
        if not self._ensure_admin_for_vpn_action("Установить туннель"):
            return
        try:
            config_path = self.save_generated_config(show_message=False)
            if config_path is None:
                return
            self._reinstall_tunnel_service(config_path)
            self._append_log("vpn", "Туннель установлен или обновлен в WireGuard.")
            self.refresh_vpn_status()
            messagebox.showinfo("WireGuard", "Туннель установлен или обновлен.")
        except Exception as exc:
            self.refresh_vpn_status()
            messagebox.showerror("WireGuard", str(exc))

    def connect_vpn(self):
        if not self._ensure_admin_for_vpn_action("Подключить VPN"):
            return
        try:
            if self.vars["use_routes"].get():
                if self.client_process is None:
                    raise RuntimeError("Сначала нужно запустить free-turn-proxy клиент.")
                if not self.routes_ready:
                    raise RuntimeError(
                        "Маршруты от routes.ps1 еще не готовы. Дождитесь строк вида 'Ensuring route to ...' в логе."
                    )
            config_path = self.save_generated_config(show_message=False)
            if config_path is None:
                return
            self._ensure_tunnel_service_ready(config_path)
            self._append_log("vpn", "VPN подключен.")
            self.refresh_vpn_status()
        except Exception as exc:
            self.refresh_vpn_status()
            messagebox.showerror("WireGuard", str(exc))

    def disconnect_vpn(self):
        if not self._ensure_admin_for_vpn_action("Отключить VPN"):
            return
        try:
            status = self._get_service_status()
            if status == "NOT_INSTALLED":
                self.refresh_vpn_status()
                messagebox.showinfo("WireGuard", "Туннель еще не установлен.")
                return
            if status == "Stopped":
                self.refresh_vpn_status()
                messagebox.showinfo("WireGuard", "VPN уже отключен.")
                return
            service_name = self._get_service_name()
            result = self._run_process(
                ["powershell", "-NoProfile", "-Command", f"Stop-Service -Name '{service_name}' -Force"],
                "vpn",
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "Не удалось остановить сервис туннеля.")
            self._append_log("vpn", "VPN отключен.")
            self.refresh_vpn_status()
        except Exception as exc:
            self.refresh_vpn_status()
            messagebox.showerror("WireGuard", str(exc))

    def connect_all(self):
        if not self._ensure_admin_for_vpn_action("Подключить все"):
            return
        self.start_connection()
        if self.client_process is None:
            return
        self.pending_connect_all = True
        self.after(250, self._continue_connect_all)

    def _continue_connect_all(self, attempts=0):
        if not self.pending_connect_all:
            return
        if self.client_process is None:
            self.pending_connect_all = False
            return
        routes_ok = (not self.vars["use_routes"].get()) or self.routes_ready
        dtls_ok = self.dtls_ready and self.dtls_ready_at is not None
        if routes_ok and dtls_ok:
            dtls_age = (datetime.now() - self.dtls_ready_at).total_seconds()
            if dtls_age < 2.0:
                self.after(250, lambda: self._continue_connect_all(attempts + 1))
                return
            self.pending_connect_all = False
            self.connect_vpn()
            return
        if attempts >= 80:
            self.pending_connect_all = False
            messagebox.showerror(
                "Канал не готов",
                "free-turn-proxy не успел подготовить маршруты или стабильный DTLS-канал. Проверьте лог и попробуйте снова.",
            )
            return
        self.after(250, lambda: self._continue_connect_all(attempts + 1))

    def copy_generated_config(self):
        try:
            generated = self._generate_wireguard_config()
        except Exception as exc:
            messagebox.showerror("WireGuard", str(exc))
            return

        self.clipboard_clear()
        self.clipboard_append(generated)
        self.update_idletasks()
        self._append_log("app", "Локальный WireGuard-конфиг скопирован в буфер обмена.")
        messagebox.showinfo("WireGuard", "Локальный WireGuard-конфиг скопирован в буфер обмена.")

    def start_connection(self):
        if self.client_process is not None:
            messagebox.showinfo("Уже запущено", "Соединение уже запущено.")
            return

        if not self.vars["link"].get().strip():
            messagebox.showerror("Нет ссылки", "Укажите ссылку VK Calls.")
            return

        client_path = Path(self.vars["client_path"].get())
        if not client_path.exists():
            messagebox.showerror("Нет client.exe", "Файл client.exe не найден.")
            return

        use_routes = self.vars["use_routes"].get()
        routes_path = Path(self.vars["routes_path"].get())
        if use_routes and not routes_path.exists():
            messagebox.showerror("Нет routes.ps1", "Файл routes.ps1 не найден.")
            return

        if use_routes and not is_admin():
            proceed = messagebox.askyesno(
                "Нет прав администратора",
                "routes.ps1 обычно требует запуск от имени администратора. Продолжить все равно?",
            )
            if not proceed:
                return

        obf_profile_value = self.vars["obf_profile"].get().strip()
        if obf_profile_value and obf_profile_value.lower() != "none" and not self.vars["obf_key"].get().strip():
            proceed = messagebox.askyesno(
                "Нет obf-key",
                "Указан obf-profile, но obf-key пустой. Продолжить?",
            )
            if not proceed:
                return

        conflicts = detect_conflicting_processes()
        if conflicts:
            proceed = messagebox.askyesno(
                "Обнаружены конфликтующие VPN/прокси",
                "Запущены потенциально конфликтующие приложения:\n\n"
                + "\n".join(conflicts)
                + "\n\nОни могут ломать TURN и WireGuard. Продолжить все равно?",
            )
            if not proceed:
                return

        if self._get_wg_config_text():
            saved_path = self.save_generated_config(show_message=False)
            if saved_path is None:
                return

        self.save_settings()
        self.routes_ready = False
        self.dtls_ready = False
        self.dtls_ready_at = None
        self.pending_connect_all = False
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._append_log("app", "Запускаю соединение...")

        client_args = [
            str(client_path),
            "-listen",
            self.vars["listen"].get().strip(),
            "-peer",
            self.vars["peer"].get().strip(),
            "-provider",
            self.vars["provider"].get().strip() or "vk",
            "-link",
            self.vars["link"].get().strip(),
        ]

        if obf_profile_value and obf_profile_value.lower() != "none":
            client_args.extend(["-obf-profile", obf_profile_value])
            obf_key = collapse_exact_double(self.vars["obf_key"].get())
            self.vars["obf_key"].set(obf_key)
            if obf_key:
                client_args.extend(["-obf-key", obf_key])

        dns_servers = self.vars["dns_servers"].get().strip()
        if dns_servers:
            client_args.extend(["-dns-servers", dns_servers])

        streams = self.vars["streams"].get().strip() or "2"
        if not self.vars["streams"].get().strip():
            self.vars["streams"].set(streams)
        client_args.extend(["-n", streams])

        if self.vars["manual_captcha"].get():
            client_args.append("-manual-captcha")

        if self.vars["debug"].get():
            client_args.append("-debug")

        self._append_log("app", f"Команда client.exe: {subprocess.list2cmdline(client_args)}")

        startupinfo = None
        creationflags = 0
        if hasattr(subprocess, "STARTUPINFO"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW

        try:
            if use_routes:
                self.routes_process = subprocess.Popen(
                    [
                        "powershell",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(routes_path),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    startupinfo=startupinfo,
                    creationflags=creationflags,
                )
                self._start_reader(self.routes_process.stdout, "routes")

            self.client_process = subprocess.Popen(
                client_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
            self._start_forwarder(self.client_process.stdout, self.routes_process.stdin if self.routes_process else None)
            self._start_watcher()
            self._set_running_state(True)
        except Exception as exc:
            self._append_log("app", f"Ошибка запуска: {exc}")
            self.stop_connection()

    def stop_connection(self):
        self.pending_connect_all = False
        self.routes_ready = False
        self.dtls_ready = False
        self.dtls_ready_at = None
        for process, name in ((self.client_process, "client"), (self.routes_process, "routes")):
            if process is None:
                continue
            try:
                process.terminate()
            except Exception:
                pass
            try:
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
            self._append_log("app", f"Остановлен процесс {name}.")

        self.client_process = None
        self.routes_process = None
        self._set_running_state(False)

    def _start_forwarder(self, source, target):
        def worker():
            route_target = target
            try:
                for line in source:
                    cleaned = line.rstrip("\r\n")
                    self.output_queue.put(("client", cleaned))
                    if route_target is not None:
                        try:
                            route_target.write(line)
                            route_target.flush()
                        except Exception:
                            route_target = None
                if route_target is not None:
                    try:
                        route_target.close()
                    except Exception:
                        pass
            except Exception as exc:
                self.output_queue.put(("app", f"Ошибка чтения client.exe: {exc}"))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.worker_threads.append(thread)

    def _start_reader(self, stream, prefix):
        def worker():
            try:
                for line in stream:
                    self.output_queue.put((prefix, line.rstrip("\r\n")))
            except Exception as exc:
                self.output_queue.put(("app", f"Ошибка чтения {prefix}: {exc}"))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.worker_threads.append(thread)

    def _start_watcher(self):
        def worker():
            if self.client_process is not None:
                self.client_process.wait()
                self.output_queue.put(("app", "client.exe завершился."))
            if self.routes_process is not None:
                try:
                    self.routes_process.wait(timeout=5)
                except Exception:
                    pass
            self.output_queue.put(("__STATE__", "stopped"))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.worker_threads.append(thread)

    def _drain_output_queue(self):
        try:
            while True:
                prefix, message = self.output_queue.get_nowait()
                if prefix == "__STATE__":
                    self.client_process = None
                    self.routes_process = None
                    self.pending_connect_all = False
                    self.routes_ready = False
                    self.dtls_ready = False
                    self.dtls_ready_at = None
                    self._set_running_state(False)
                    continue
                if prefix == "routes" and self._is_routes_ready_line(message):
                    self.routes_ready = True
                if prefix == "client" and "Established DTLS connection" in message:
                    self.dtls_ready = True
                    self.dtls_ready_at = datetime.now()
                self._append_log(prefix, message)
        except queue.Empty:
            pass
        self.after(100, self._drain_output_queue)

    def _append_log(self, prefix, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} [{prefix}] {message}"
        try:
            with self.log_file_path.open("a", encoding="utf-8") as log_file:
                log_file.write(line + "\n")
        except Exception:
            pass
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _set_running_state(self, running):
        self.status_var.set("Подключено" if running else "Отключено")
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")

    def on_close(self):
        self.save_settings()
        self.stop_connection()
        self.destroy()

    def open_logs_dir(self):
        try:
            os.startfile(str(LOGS_DIR))
        except Exception as exc:
            messagebox.showerror("Логи", f"Не удалось открыть папку логов: {exc}")


if __name__ == "__main__":
    app = FreeTurnProxyApp()
    app.mainloop()
