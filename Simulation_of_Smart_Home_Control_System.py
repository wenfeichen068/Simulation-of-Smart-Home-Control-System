import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import datetime
import time
import threading
import base64
import hashlib


# ==============================
# 1. 安全与加密模块
# ==============================
class SecurityUtils:
    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def encrypt_data(data_str):
        return base64.b64encode(data_str.encode()).decode()

    @staticmethod
    def decrypt_data(encrypted_str):
        try:
            return base64.b64decode(encrypted_str.encode()).decode()
        except:
            return "{}"


# ==============================
# 2. 设备类定义
# ==============================
class Device:
    def __init__(self, dev_id, name, owner, dev_type):
        self.id = dev_id
        self.name = name
        self.owner = owner
        self.type = dev_type
        self.status = "OFF"
        self.shared_users = []

    def toggle(self):
        self.status = "ON" if self.status == "OFF" else "OFF"
        return f"状态变为 {self.status}"

    def set_attr(self, val):
        return "不支持设置属性"

    def get_details(self):
        return f"状态: {self.status}"

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "owner": self.owner,
            "type": self.type, "status": self.status, "shared_users": self.shared_users
        }


class Light(Device):
    def __init__(self, *args):
        super().__init__(*args)
        self.brightness = 50

    def set_attr(self, val):
        self.brightness = int(val)
        return f"亮度设为 {self.brightness}"

    def get_details(self):
        return f"状态: {self.status} | 亮度: {self.brightness}"

    def to_dict(self):
        d = super().to_dict()
        d['brightness'] = self.brightness
        return d


class AirConditioner(Device):
    def __init__(self, *args):
        super().__init__(*args)
        self.temperature = 26

    def set_attr(self, val):
        self.temperature = int(val)
        return f"温度设为 {self.temperature}°C"

    def get_details(self):
        return f"状态: {self.status} | 温度: {self.temperature}°C"

    def to_dict(self):
        d = super().to_dict()
        d['temperature'] = self.temperature
        return d


class Curtain(Device):
    def __init__(self, *args):
        super().__init__(*args)
        self.open_pct = 0

    def set_attr(self, val):
        self.open_pct = int(val)
        return f"窗帘开合度 {self.open_pct}%"

    def get_details(self):
        return f"状态: {'开启' if self.open_pct > 0 else '关闭'} | 开合: {self.open_pct}%"

    def to_dict(self):
        d = super().to_dict()
        d['open_pct'] = self.open_pct
        return d


class Camera(Device):
    def __init__(self, *args):
        super().__init__(*args)
        self.angle = 0

    def set_attr(self, val):
        self.angle = int(val)
        return f"角度转至 {self.angle}°"

    def get_details(self):
        return f"状态: {self.status} | 角度: {self.angle}°"

    def to_dict(self):
        d = super().to_dict()
        d['angle'] = self.angle
        return d


# ==============================
# 3. 后端系统核心 (含权限逻辑)
# ==============================
LOG_FILE = "logs.txt"
DATA_FILE = "data.json"


class BackendSystem:
    def __init__(self):
        self.devices = {}
        self.users = {}
        self.scheduled_tasks = []
        self.automation_rules = []
        self.current_user = None
        self.use_encryption = False

        self.load_data()
        self.init_default_rules()

        self.running = True
        self.timer_thread = threading.Thread(target=self.scheduler_loop, daemon=True)
        self.timer_thread.start()

    # --- 核心权限判断函数 ---
    def get_user_role(self):
        if self.current_user and self.current_user in self.users:
            return self.users[self.current_user]['role']
        return "guest"

    def can_view_device(self, dev):
        """判断是否能在列表中看到该设备"""
        role = self.get_user_role()
        # 管理员看所有
        if role == 'admin': return True
        # 普通用户看: 自己的 + 别人共享给我的
        if dev.owner == self.current_user: return True
        if self.current_user in dev.shared_users: return True
        return False

    def can_control_device(self, dev):
        """判断是否有操作权 (开关/属性)"""
        role = self.get_user_role()
        # 管理员有最高控制权
        if role == 'admin': return True
        # 所有者有权
        if dev.owner == self.current_user: return True
        # 被共享者有权
        if self.current_user in dev.shared_users: return True
        return False

    def can_manage_share(self, dev):
        """判断是否有权分享设备 (仅所有者和管理员)"""
        role = self.get_user_role()
        if role == 'admin': return True
        if dev.owner == self.current_user: return True
        # 注意: 被共享者(Shared User)不能再去分享给别人
        return False

    def can_delete_device(self, dev):
        """判断是否有权删除 (仅所有者和管理员)"""
        return self.can_manage_share(dev)

    # --- 数据与逻辑 ---
    def log(self, action, details):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        plain_log = f"[{timestamp}] 用户:{self.current_user} | 操作:{action} | 详情:{details}"
        print(plain_log)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(plain_log + "\n")

    def save_data(self):
        data = {
            "is_encrypted": self.use_encryption,
            "users": self.users,
            "devices": [d.to_dict() for d in self.devices.values()]
        }
        json_str = json.dumps(data, ensure_ascii=False, indent=4)
        content = SecurityUtils.encrypt_data(json_str) if self.use_encryption else json_str

        with open(DATA_FILE, "w", encoding="utf-8") as f:
            f.write(content)

    def load_data(self):
        if not os.path.exists(DATA_FILE):
            self._init_defaults()
            return
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                content = f.read()
            try:
                data = json.loads(content)
                if isinstance(data, str): raise ValueError
            except:
                print("检测到密文，解密中...")
                data = json.loads(SecurityUtils.decrypt_data(content))

            self.use_encryption = data.get("is_encrypted", False)

            # 兼容旧数据格式
            loaded_users = data.get("users", {})
            if isinstance(loaded_users, list):
                self._init_defaults()  # 数据格式不对，重置
            else:
                self.users = loaded_users

            self._restore_devices(data.get("devices", []))
        except Exception as e:
            print(f"数据加载错误，重置默认: {e}")
            self._init_defaults()

    def _init_defaults(self):
        self.users = {
            "admin": {"pass": SecurityUtils.hash_password("admin123"), "role": "admin"},
            "user1": {"pass": SecurityUtils.hash_password("123456"), "role": "user"},
            "user2": {"pass": SecurityUtils.hash_password("123456"), "role": "user"}
        }
        self.devices = {
            "light_living": Light("light_living", "客厅灯", "admin", "Light"),
            "cam_gate": Camera("cam_gate", "大门监控", "user1", "Camera")
        }
        # 预设共享: 客厅灯共享给 user1
        self.devices["light_living"].shared_users.append("user1")

    def _restore_devices(self, dev_list):
        self.devices = {}
        for d in dev_list:
            dtype = d['type']
            if dtype == 'Light':
                dev = Light(d['id'], d['name'], d['owner'], dtype)
            elif dtype == 'AirConditioner':
                dev = AirConditioner(d['id'], d['name'], d['owner'], dtype)
            elif dtype == 'Curtain':
                dev = Curtain(d['id'], d['name'], d['owner'], dtype)
            elif dtype == 'Camera':
                dev = Camera(d['id'], d['name'], d['owner'], dtype)
            else:
                dev = Device(d['id'], d['name'], d['owner'], 'Generic')

            dev.status = d['status']
            dev.shared_users = d.get('shared_users', [])
            if hasattr(dev, 'brightness'): dev.brightness = d.get('brightness', 50)
            if hasattr(dev, 'temperature'): dev.temperature = d.get('temperature', 26)
            if hasattr(dev, 'open_pct'): dev.open_pct = d.get('open_pct', 0)
            if hasattr(dev, 'angle'): dev.angle = d.get('angle', 0)
            self.devices[dev.id] = dev

    def delete_device(self, dev_id):
        if dev_id in self.devices:
            dev = self.devices[dev_id]
            # 权限检查
            if not self.can_delete_device(dev):
                return False, "权限拒绝：只有所有者或管理员可删除"

            del self.devices[dev_id]
            self.log("删除设备", f"ID:{dev_id} 被 {self.current_user} 删除")
            self.save_data()
            return True, "设备已删除"
        return False, "设备不存在"

    def login(self, username, password):
        if username in self.users:
            if self.users[username]['pass'] == SecurityUtils.hash_password(password):
                self.current_user = username
                role = self.users[username]['role']
                self.log("登录", f"角色:{role}")
                return True, role
        return False, None

    def get_viewable_devices(self):
        """返回当前用户可见的设备列表"""
        visible = []
        for dev in self.devices.values():
            if self.can_view_device(dev):
                visible.append(dev)
        return visible

    # --- 任务与自动化 ---
    def add_schedule(self, time_str, dev_id, action):
        if dev_id in self.devices:
            # 添加任务也需要检查权限
            if not self.can_control_device(self.devices[dev_id]):
                return False, "无权对该设备设置任务"
            self.scheduled_tasks.append({'time': time_str, 'dev_id': dev_id, 'action': action, 'last_run': ''})
            self.log("添加任务", f"{time_str} {dev_id} {action}")
            return True, "任务添加成功"
        return False, "设备不存在"

    def scheduler_loop(self):
        while self.running:
            now_str = datetime.datetime.now().strftime("%H:%M")
            today_str = datetime.datetime.now().strftime("%Y-%m-%d")
            for task in self.scheduled_tasks:
                if task['time'] == now_str and task['last_run'] != today_str:
                    self.execute_task(task)
                    task['last_run'] = today_str
            time.sleep(1)

    def execute_task(self, task):
        dev_id = task['dev_id']
        if dev_id in self.devices:
            dev = self.devices[dev_id]
            dev.status = task['action']
            print(f"[自动任务] {dev.name} {task['action']}")
            self.save_data()

    def init_default_rules(self):
        self.automation_rules.append({
            "name": "高温自动开空调 (>30°C)",
            "check": lambda data: data.get('temp', 0) > 30,
            "action": self._rule_action_ac_on
        })

    def _rule_action_ac_on(self):
        triggered = []
        for dev in self.devices.values():
            # 自动化规则通常由系统执行，忽略用户权限，或默认只操作用户有权的设备
            # 这里简化为系统自动操作所有符合条件的设备
            if isinstance(dev, AirConditioner) and dev.status == "OFF":
                dev.status = "ON"
                triggered.append(dev.name)
        return triggered

    def run_automation_check(self, sensor_data):
        results = []
        triggered_any = False
        self.log("传感器扫描", str(sensor_data))
        for rule in self.automation_rules:
            if rule["check"](sensor_data):
                affected_devs = rule["action"]()
                if affected_devs:
                    triggered_any = True
                    results.append(f"触发[{rule['name']}]: {', '.join(affected_devs)}")
        if triggered_any:
            self.save_data()
            return "\n".join(results)
        else:
            return "无规则触发"


# ==============================
# 4. GUI 界面
# ==============================
class SmartHomeGUI:
    def __init__(self, root):
        self.sys = BackendSystem()
        self.root = root
        self.role = None
        self.root.title("Simulation of Smart Home Control System ")
        self.root.geometry("950x650")
        self.show_login()

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_frame()
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True)
        tk.Label(frame, text="系统登录", font=("Arial", 16, "bold")).pack(pady=10)
        tk.Label(frame, text="用户名 (admin / user1 ):").pack()
        self.entry_user = tk.Entry(frame)
        self.entry_user.pack(pady=5)
        tk.Label(frame, text="密码 (admin123 / 123456):").pack()
        self.entry_pass = tk.Entry(frame, show="*")
        self.entry_pass.pack(pady=5)
        tk.Button(frame, text="登录", command=self.do_login, bg="#4CAF50", fg="white", width=20).pack(pady=15)

    def do_login(self):
        u = self.entry_user.get()
        p = self.entry_pass.get()
        success, role = self.sys.login(u, p)
        if success:
            self.role = role
            self.show_dashboard()
        else:
            messagebox.showerror("错误", "用户名或密码错误")

    def show_dashboard(self):
        self.clear_frame()

        # Top Bar
        top_bar = tk.Frame(self.root, bg="#333", height=50)
        top_bar.pack(side=tk.TOP, fill=tk.X)

        tk.Label(top_bar, text=f"用户: {self.sys.current_user} | 身份: {self.role}",
                 fg="white", bg="#333", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=15)

        self.encrypt_var = tk.BooleanVar(value=self.sys.use_encryption)
        cb = tk.Checkbutton(top_bar, text="启用加密存储", variable=self.encrypt_var,
                            command=self.toggle_encryption, bg="#333", fg="orange", selectcolor="#333")
        cb.pack(side=tk.LEFT, padx=20)

        tk.Button(top_bar, text="注销", command=self.show_login, bg="#f44336", fg="white").pack(side=tk.RIGHT, padx=10,
                                                                                                pady=5)

        # Left Panel
        left_panel = tk.Frame(self.root, width=200, bg="#f0f0f0")
        left_panel.pack(side=tk.LEFT, fill=tk.Y)

        btn_style = {"fill": tk.X, "pady": 5, "padx": 10}
        tk.Label(left_panel, text="管理", bg="#f0f0f0", fg="gray").pack(pady=(10, 0))
        tk.Button(left_panel, text="添加设备", command=self.popup_add_device).pack(**btn_style)
        tk.Button(left_panel, text="删除选中", command=self.action_delete_selected, bg="#FFCDD2").pack(**btn_style)
        tk.Button(left_panel, text="刷新列表", command=self.refresh_list).pack(**btn_style)

        tk.Label(left_panel, text="自动化", bg="#f0f0f0", fg="gray").pack(pady=(10, 0))
        tk.Button(left_panel, text="定时任务", command=self.popup_add_schedule).pack(**btn_style)
        tk.Button(left_panel, text="模拟传感器", command=self.popup_sensor_sim, bg="#2196F3", fg="white").pack(
            **btn_style)

        # Main List
        cols = ("ID", "Name", "Type", "Owner", "Shared", "Detail")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings")

        self.tree.heading("ID", text="ID");
        self.tree.column("ID", width=60)
        self.tree.heading("Name", text="名称");
        self.tree.column("Name", width=100)
        self.tree.heading("Type", text="类型");
        self.tree.column("Type", width=80)
        self.tree.heading("Owner", text="拥有者");
        self.tree.column("Owner", width=80)
        self.tree.heading("Shared", text="共享给");
        self.tree.column("Shared", width=120)
        self.tree.heading("Detail", text="状态详情");
        self.tree.column("Detail", width=180)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tree.bind("<Double-1>", self.on_device_double_click)

        self.refresh_list()

    def toggle_encryption(self):
        self.sys.use_encryption = self.encrypt_var.get()
        self.sys.save_data()
        messagebox.showinfo("提示", "存储设置已更新")

    def refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        # 仅获取可见设备
        for d in self.sys.get_viewable_devices():
            shared_str = ",".join(d.shared_users) if d.shared_users else "无"
            self.tree.insert("", tk.END, values=(d.id, d.name, d.type, d.owner, shared_str, d.get_details()))

    def action_delete_selected(self):
        selected_item = self.tree.selection()
        if not selected_item: return
        dev_id = self.tree.item(selected_item[0], "values")[0]

        if messagebox.askyesno("删除", f"确定删除设备 {dev_id} 吗?"):
            success, msg = self.sys.delete_device(dev_id)
            if success:
                messagebox.showinfo("成功", msg)
                self.refresh_list()
            else:
                messagebox.showerror("失败", msg)

    # --- 弹窗逻辑 ---
    def popup_add_device(self):
        win = tk.Toplevel(self.root)
        win.title("添加")
        tk.Label(win, text="类型:").grid(row=0, column=0)
        type_var = tk.StringVar(value="Light")
        ttk.Combobox(win, textvariable=type_var, values=["Light", "AC", "Curtain", "Camera"]).grid(row=0, column=1)
        tk.Label(win, text="ID:").grid(row=1, column=0)
        id_entry = tk.Entry(win)
        id_entry.grid(row=1, column=1)
        tk.Label(win, text="名称:").grid(row=2, column=0)
        name_entry = tk.Entry(win)
        name_entry.grid(row=2, column=1)

        def confirm():
            tid, tname = id_entry.get(), name_entry.get()
            if not tid or tid in self.sys.devices:
                messagebox.showerror("错误", "ID无效或已存在")
                return
            t = type_var.get()
            user = self.sys.current_user
            if t == "Light":
                obj = Light(tid, tname, user, t)
            elif t == "AC":
                obj = AirConditioner(tid, tname, user, t)
            elif t == "Curtain":
                obj = Curtain(tid, tname, user, t)
            elif t == "Camera":
                obj = Camera(tid, tname, user, t)
            self.sys.devices[tid] = obj
            self.sys.save_data()
            self.refresh_list()
            win.destroy()

        tk.Button(win, text="保存", command=confirm).grid(row=3, columnspan=2, pady=10)

    def popup_add_schedule(self):
        win = tk.Toplevel(self.root)
        win.title("任务")
        tk.Label(win, text="ID:").grid(row=0, column=0)
        id_entry = tk.Entry(win)
        id_entry.grid(row=0, column=1)
        tk.Label(win, text="时间(HH:MM):").grid(row=1, column=0)
        time_entry = tk.Entry(win)
        time_entry.insert(0, datetime.datetime.now().strftime("%H:%M"))
        time_entry.grid(row=1, column=1)
        tk.Label(win, text="动作:").grid(row=2, column=0)
        act_var = tk.StringVar(value="ON")
        ttk.Combobox(win, textvariable=act_var, values=["ON", "OFF"]).grid(row=2, column=1)

        def confirm():
            # 权限检查在后端 add_schedule 中
            succ, msg = self.sys.add_schedule(time_entry.get(), id_entry.get(), act_var.get())
            if succ:
                messagebox.showinfo("成功", msg); win.destroy()
            else:
                messagebox.showerror("失败", msg)

        tk.Button(win, text="添加", command=confirm).grid(row=3, columnspan=2)

    def popup_sensor_sim(self):
        win = tk.Toplevel(self.root)
        win.title("传感器")
        tk.Label(win, text="温度:").pack()
        temp_scale = tk.Scale(win, from_=0, to=50, orient=tk.HORIZONTAL)
        temp_scale.set(25);
        temp_scale.pack()
        tk.Label(win, text="有人:").pack()
        pres_var = tk.BooleanVar(value=True)
        tk.Checkbutton(win, variable=pres_var).pack()

        def run():
            res = self.sys.run_automation_check({"temp": temp_scale.get(), "presence": pres_var.get()})
            self.refresh_list()
            messagebox.showinfo("结果", res)

        tk.Button(win, text="触发", command=run).pack()

    # --- 核心：控制面板与权限检查 ---
    def on_device_double_click(self, event):
        item = self.tree.selection()
        if not item: return
        dev_id = self.tree.item(item[0], "values")[0]
        dev = self.sys.devices.get(dev_id)
        if not dev: return

        # 检查控制权限
        can_control = self.sys.can_control_device(dev)
        # 检查管理(共享)权限
        can_share = self.sys.can_manage_share(dev)

        win = tk.Toplevel(self.root)
        title_suffix = "" if can_control else " (无控制权 - 仅查看)"
        win.title(f"控制: {dev.name}{title_suffix}")

        # 状态显示
        tk.Label(win, text=f"当前状态: {dev.status}", font=("Arial", 12)).pack(pady=10)

        # 如果无权限，禁用控件状态
        ui_state = "normal" if can_control else "disabled"

        tk.Button(win, text="电源开关", state=ui_state,
                  command=lambda: self._act(dev, "toggle", None, win)).pack(pady=5)

        if isinstance(dev, (Light, AirConditioner, Curtain, Camera)):
            f = tk.Frame(win, pady=10)
            f.pack()
            limit = 30 if isinstance(dev, AirConditioner) else (180 if isinstance(dev, Camera) else 100)
            slider = tk.Scale(f, from_=0, to=limit, orient=tk.HORIZONTAL, length=200, state=ui_state)

            # 设置初始值
            if isinstance(dev, Light):
                val = dev.brightness
            elif isinstance(dev, AirConditioner):
                val = dev.temperature
            elif isinstance(dev, Curtain):
                val = dev.open_pct
            elif isinstance(dev, Camera):
                val = dev.angle
            slider.set(val)
            slider.pack()

            tk.Button(f, text="应用属性", state=ui_state,
                      command=lambda: self._act(dev, "attr", slider.get(), win)).pack()

        # 共享区域 (仅所有者/管理员可见)
        if can_share:
            tk.Label(win, text="--- 设备共享 ---", fg="blue").pack(pady=(15, 5))
            tk.Label(win, text="共享给用户:").pack()
            e = tk.Entry(win)
            e.pack()
            tk.Button(win, text="确定共享",
                      command=lambda: self._act(dev, "share", e.get(), win)).pack(pady=5)
        elif not can_control:
            tk.Label(win, text="您没有权限控制此设备", fg="red").pack(pady=10)
        else:
            # 有控制权但无分享权（即被分享的用户）
            tk.Label(win, text="(作为被分享者，您无法再次分享此设备)", fg="gray", font=("Arial", 8)).pack(pady=10)

    def _act(self, dev, type, val, win):
        if type == "toggle":
            msg = dev.toggle()
        elif type == "attr":
            msg = dev.set_attr(val)
        elif type == "share":
            # 再次校验防止绕过UI
            if not self.sys.can_manage_share(dev):
                messagebox.showerror("失败", "无权共享")
                return
            if val and val not in dev.shared_users:
                dev.shared_users.append(val)
                msg = f"已共享给 {val}"
            else:
                msg = "用户无效或已存在"

        self.sys.log("操作", f"{dev.name} {msg}")
        self.sys.save_data()
        self.refresh_list()
        messagebox.showinfo("结果", msg)
        if type != "share": win.destroy()  # 分享后不关闭窗口方便继续操作


if __name__ == "__main__":
    root = tk.Tk()
    app = SmartHomeGUI(root)


    def on_closing():
        app.sys.running = False
        root.destroy()


    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()