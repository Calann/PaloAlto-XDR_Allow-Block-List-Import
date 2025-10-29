import os
import re
import csv
import json
import time
import requests
import secrets
import string
import hashlib
from datetime import datetime, timezone
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from cryptography.fernet import Fernet

BASE_DIR = r"C:\ProgramData\Xdr-API-Tool"
KEY_DIR = os.path.join(BASE_DIR, "key")
KEY_PATH = os.path.join(KEY_DIR, "key.key")
ALLOW_DIR = os.path.join(BASE_DIR, "Allowlist")
BLOCK_DIR = os.path.join(BASE_DIR, "Blocklist")
APIKEY_DIR = os.path.join(BASE_DIR, "XDR-APIkey")

def ensure_dirs():
    for p in [BASE_DIR, KEY_DIR, ALLOW_DIR, BLOCK_DIR, APIKEY_DIR]:
        os.makedirs(p, exist_ok=True)

def sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\n\r\t]', "_", name).strip() or "untitled"

def now_stamp():
    return datetime.now().strftime("%Y%m%d-%H%M")

def generate_key():
    ensure_dirs()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

def load_key():
    ensure_dirs()
    if not os.path.exists(KEY_PATH):
        return generate_key()
    with open(KEY_PATH, "rb") as f:
        return f.read()

def encrypt_config(data, filename):
    key = load_key()
    fernet = Fernet(key)
    enc = fernet.encrypt(json.dumps(data).encode("utf-8"))
    with open(filename, "wb") as f:
        f.write(enc)

def decrypt_config(filename):
    key = load_key()
    fernet = Fernet(key)
    with open(filename, "rb") as f:
        enc = f.read()
    return json.loads(fernet.decrypt(enc).decode("utf-8"))

def generate_headers(api_key_id, api_key):
    nonce = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
    auth_key = f"{api_key}{nonce}{timestamp}".encode("utf-8")
    api_key_hash = hashlib.sha256(auth_key).hexdigest()
    return {
        "x-xdr-timestamp": str(timestamp),
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

def load_enabled_hashes(file_path):
    data = []
    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            h = row.get("Hash")
            s = row.get("Status")
            c = row.get("Comment") or ""
            if h and s and s.strip().lower() == "enabled":
                data.append({"hash": h.strip(), "comment": c.strip()})
    return data

def write_log(mode, lines, total, ok, fail, elapsed):
    target_dir = ALLOW_DIR if mode == "Allow" else BLOCK_DIR
    filename = os.path.join(target_dir, f"{now_stamp()}-result.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"上传类型: {mode} List\n")
        f.write(f"上传时间: {datetime.now()}\n")
        f.write(f"总条数: {total}  成功: {ok}  失败: {fail}\n")
        f.write(f"耗时: {elapsed:.2f} 秒\n\n")
        f.write("\n".join(lines))
    return filename

def upload_hashes(records, api_url, api_id, api_key, mode, progress_cb=None, status_cb=None):
    start_time = time.time()
    endpoint = "allowlist" if mode == "Allow" else "blocklist"
    url = f"{api_url}/public_api/v1/hash_exceptions/{endpoint}"
    headers = generate_headers(api_id, api_key)

    total = len(records)
    ok = fail = 0
    lines = []

    for i, rec in enumerate(records, 1):
        body = {
            "request_data": {
                "hash_list": [rec["hash"]],
                "comment": rec["comment"],
                "incident_id": 0
            }
        }
        try:
            res = requests.post(url, headers=headers, json=body)
            if res.status_code == 200:
                ok += 1
                lines.append(f"[OK] {rec['hash']} ({rec['comment']})")
            else:
                fail += 1
                lines.append(f"[FAIL {res.status_code}] {rec['hash']} -> {res.text}")
        except Exception as e:
            fail += 1
            lines.append(f"[EXCEPTION] {rec['hash']} {e}")

        if progress_cb:
            progress_cb(i / total * 100)
        if status_cb:
            status_cb(f"{mode} 上传中：{i}/{total}，成功 {ok}，失败 {fail}")

    elapsed = time.time() - start_time
    log_path = write_log(mode, lines, total, ok, fail, elapsed)
    messagebox.showinfo(
        "上传结果",
        f"✅ {mode} List 上传完成\n总数: {total}\n成功: {ok}\n失败: {fail}\n耗时: {elapsed:.2f} 秒\n日志: {log_path}"
    )

class XDRToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 XDR Hash List 管理工具")
        self.root.geometry("960x700")
        self.root.minsize(960, 700)

        self.records = []
        self.filtered_records = []
        self.file_path = tk.StringVar()
        self.api_url = tk.StringVar()
        self.api_id = tk.StringVar()
        self.api_key = tk.StringVar()
        self.status_text = tk.StringVar(value="就绪")
        self.search_text = tk.StringVar()

        frm_file = ttk.Frame(root, padding=10)
        frm_file.pack(fill="x")
        ttk.Label(frm_file, text="TSV 文件:").pack(side="left")
        ttk.Entry(frm_file, textvariable=self.file_path, width=70).pack(side="left", padx=6)
        ttk.Button(frm_file, text="选择文件", command=self.choose_file).pack(side="left")

        frm_search = ttk.Frame(root, padding=(10, 0))
        frm_search.pack(fill="x")
        ttk.Label(frm_search, text="搜索（Hash / Comment）:").pack(side="left")
        ttk.Entry(frm_search, textvariable=self.search_text, width=30).pack(side="left", padx=6)
        ttk.Button(frm_search, text="筛选", command=self.apply_filter).pack(side="left")
        ttk.Button(frm_search, text="重置", command=self.reset_filter).pack(side="left", padx=5)

        frm_api = ttk.LabelFrame(root, text="API 设置", padding=10)
        frm_api.pack(fill="x", padx=10, pady=8)
        ttk.Label(frm_api, text="API URL:").grid(row=0, column=0, sticky="e")
        ttk.Entry(frm_api, textvariable=self.api_url, width=56).grid(row=0, column=1, padx=6)
        ttk.Label(frm_api, text="API ID:").grid(row=1, column=0, sticky="e")
        ttk.Entry(frm_api, textvariable=self.api_id, width=56).grid(row=1, column=1, padx=6)
        ttk.Label(frm_api, text="API Key:").grid(row=2, column=0, sticky="e")
        ttk.Entry(frm_api, textvariable=self.api_key, width=56, show="*").grid(row=2, column=1, padx=6)
        ttk.Button(frm_api, text="保存配置(加密)", command=self.save_config_flow).grid(row=0, column=2, padx=10)
        ttk.Button(frm_api, text="加载配置", command=self.load_config_flow).grid(row=1, column=2, padx=10)

        frm_table = ttk.Frame(root)
        frm_table.pack(fill="both", expand=True, padx=10, pady=10)
        self.tree = ttk.Treeview(frm_table, columns=("hash", "comment"), show="headings", height=12)
        self.tree.heading("hash", text="Hash")
        self.tree.heading("comment", text="Comment")
        self.tree.column("hash", width=520)
        self.tree.column("comment", width=350)
        yscroll = ttk.Scrollbar(frm_table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        frm_bottom = ttk.Frame(root, padding=10)
        frm_bottom.pack(fill="x", side="bottom")

        self.progress = ttk.Progressbar(frm_bottom, orient="horizontal", mode="determinate", length=400)
        self.progress.pack(side="left", padx=10)
        ttk.Label(frm_bottom, textvariable=self.status_text, width=40, anchor="w").pack(side="left", padx=10)
        ttk.Button(frm_bottom, text="上传到 XDR", command=self.choose_upload_mode).pack(side="right", padx=6)
        ttk.Button(frm_bottom, text="退出", command=root.quit).pack(side="right")

    def choose_file(self):
        file = filedialog.askopenfilename(filetypes=[("TSV 文件", "*.tsv")])
        if file:
            self.file_path.set(file)
            self.records = load_enabled_hashes(file)
            self.filtered_records = self.records.copy()
            self.refresh_table()
            messagebox.showinfo("加载完成", f"读取到 {len(self.records)} 条 Enabled 条目。")

    def refresh_table(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for rec in self.filtered_records[:500]:
            self.tree.insert("", "end", values=(rec["hash"], rec["comment"]))

    def apply_filter(self):
        q = self.search_text.get().strip().lower()
        if not q:
            self.reset_filter()
            return
        self.filtered_records = [r for r in self.records if q in r["hash"].lower() or q in r["comment"].lower()]
        self.refresh_table()

    def reset_filter(self):
        self.filtered_records = self.records.copy()
        self.search_text.set("")
        self.refresh_table()

    def save_config_flow(self):
        desc = simpledialog.askstring("保存配置(加密)", "请输入描述（可为空，取消不保存）：")
        if desc is None:
            return
        desc = desc.strip()
        fname = f"{sanitize_filename(desc)}.enc" if desc else f"{now_stamp()}-api.enc"
        path = os.path.join(APIKEY_DIR, fname)
        data = {"url": self.api_url.get(), "id": self.api_id.get(), "key": self.api_key.get(), "desc": desc or "无描述"}
        encrypt_config(data, path)
        messagebox.showinfo("保存成功", f"配置已保存：\n{path}")

    def load_config_flow(self):
        file = filedialog.askopenfilename(initialdir=APIKEY_DIR, filetypes=[("加密配置", "*.enc")])
        if not file:
            return
        data = decrypt_config(file)
        self.api_url.set(data.get("url", ""))
        self.api_id.set(data.get("id", ""))
        self.api_key.set(data.get("key", ""))
        messagebox.showinfo("加载成功", f"描述：{data.get('desc', '')}")

    def choose_upload_mode(self):
        if not self.records:
            messagebox.showwarning("未加载数据", "请先选择 TSV 文件。")
            return
        if not self.api_url.get() or not self.api_id.get() or not self.api_key.get():
            messagebox.showwarning("缺少信息", "请完整填写 API URL、API ID、API Key。")
            return

        win = tk.Toplevel(self.root)
        win.title("选择上传目标")
        ttk.Label(win, text="请选择上传到哪个列表：", padding=10).pack()
        frm = ttk.Frame(win, padding=10)
        frm.pack()
        ttk.Button(frm, text="上传到 Allow List", command=lambda: self.start_upload("Allow", win)).grid(row=0, column=0, padx=10)
        ttk.Button(frm, text="上传到 Block List", command=lambda: self.start_upload("Block", win)).grid(row=0, column=1, padx=10)
        win.grab_set()

    def start_upload(self, mode, win):
        win.destroy()
        if messagebox.askyesno("确认上传", f"确认上传到 {mode} List？\nAPI URL: {self.api_url.get()}"):
            self.progress["value"] = 0
            upload_hashes(
                self.filtered_records,
                self.api_url.get(),
                self.api_id.get(),
                self.api_key.get(),
                mode,
                progress_cb=self.update_progress,
                status_cb=self.update_status
            )

    def update_progress(self, percent):
        self.progress["value"] = percent
        self.root.update_idletasks()

    def update_status(self, text):
        self.status_text.set(text)
        self.root.update_idletasks()

if __name__ == "__main__":
    ensure_dirs()
    root = tk.Tk()
    app = XDRToolApp(root)
    root.mainloop()
