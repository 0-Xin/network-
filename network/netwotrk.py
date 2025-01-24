import psutil
import socket  # 引入 socket 模块
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import json
import re
from ip_config import IPConfig
import ipaddress
import threading
import queue
import os
from tkinter import scrolledtext
import hashlib
import uuid
import wmi
import winreg
from datetime import datetime

# 获取系统的网络接口
def get_network_interfaces():
    try:
        # 使用 netsh interface ipv4 show interfaces 命令获取更详细的网卡信息
        output = subprocess.check_output('netsh interface show interface', shell=True).decode('gbk')
        lines = output.split('\n')
        
        interfaces = []
        for line in lines:
            line = line.strip()
            if "已启用" in line:  # 只获取已启用的网卡
                # 分割行内容并获取网卡名称
                parts = line.split()
                if len(parts) >= 4:
                    interface = " ".join(parts[3:])  # 获取最后一部分作为网卡名称
                    if interface and "Loopback" not in interface:
                        interfaces.append(interface)
        
        print(f"Debug - Found interfaces: {interfaces}")
        return interfaces
    except Exception as e:
        print(f"Error getting network interfaces: {str(e)}")
        return []

# 获取网卡的IP地址等信息
def get_ip_details(interface):
    ip_info = {}
    try:
        # 使用 netsh interface ip show config 命令获取IP配置
        cmd = f'netsh interface ip show config "{interface}"'
        output = subprocess.check_output(cmd, shell=True).decode('gbk')
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if "IP 地址" in line or "IPv4 地址" in line:
                ip_info['IP'] = line.split(":")[-1].strip()
            elif "子网掩码" in line:
                ip_info['Mask'] = line.split(":")[-1].strip()
            elif "默认网关" in line:
                ip_info['Gateway'] = line.split(":")[-1].strip()
                
        # 如果没有找到某些信息，设置为N/A
        if 'IP' not in ip_info:
            ip_info['IP'] = 'N/A'
        if 'Mask' not in ip_info:
            ip_info['Mask'] = 'N/A'
        if 'Gateway' not in ip_info:
            ip_info['Gateway'] = 'N/A'
            
        print(f"Debug - Interface: {interface}")
        print(f"Debug - IP details: {ip_info}")
            
    except Exception as e:
        print(f"Error getting IP details: {str(e)}")
        ip_info = {'IP': 'N/A', 'Mask': 'N/A', 'Gateway': 'N/A'}
    
    return ip_info

# 获取网卡的默认网关
def get_gateway(interface):
    try:
        # 使用 ipconfig 命令获取网关信息
        output = subprocess.check_output('ipconfig /all', shell=True).decode('gbk')
        # 分割成行
        lines = output.split('\n')
        # 查找指定网卡的部分
        interface_found = False
        for line in lines:
            if interface in line:
                interface_found = True
            if interface_found and "默认网关" in line:
                return line.split(":")[-1].strip()
    except:
        return "N/A"
    return "N/A"

# 更新IP地址
def update_ip(interface, new_ip, new_mask, new_gateway, new_dns=None):
    try:
        # 使用管理员权限执行命令
        cmd = f'netsh interface ip set address "{interface}" static {new_ip} {new_mask} {new_gateway}'
        print(f"Debug - 执行命令: {cmd}")
        
        # 使用管理员权限执行命令
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='gbk')
        
        if result.returncode != 0:
            error_output = result.stderr if result.stderr else result.stdout
            raise Exception(f"命令执行失败: {error_output}")
        
        # 如果提供了DNS，则设置DNS
        if new_dns:
            dns_cmd = f'netsh interface ip set dns "{interface}" static {new_dns}'
            print(f"Debug - 执行DNS命令: {dns_cmd}")
            dns_result = subprocess.run(dns_cmd, shell=True, capture_output=True, text=True, encoding='gbk')
            if dns_result.returncode != 0:
                error_output = dns_result.stderr if dns_result.stderr else dns_result.stdout
                raise Exception(f"DNS设置失败: {error_output}")
            
        messagebox.showinfo("成功", f"{interface} 的IP已更新为 {new_ip}")
    except subprocess.CalledProcessError as e:
        error_msg = f"更新IP时出错: {str(e)}\n命令输出: {e.output if hasattr(e, 'output') else '无输出'}"
        print(f"Debug - {error_msg}")
        messagebox.showerror("错误", error_msg)
    except Exception as e:
        error_msg = f"更新IP时出错: {str(e)}"
        print(f"Debug - {error_msg}")
        messagebox.showerror("错误", error_msg)

class AuthWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("网卡 IP 管理工具 - 授权验证")
        self.root.geometry("400x300")
        self.setup_ui()
        
    def setup_ui(self):
        # 标题和作者信息
        title_frame = ttk.Frame(self.root, padding="10")
        title_frame.pack(fill='x')
        
        ttk.Label(title_frame, text="网卡 IP 管理工具", 
                 font=('黑体', 16, 'bold')).pack()
        ttk.Label(title_frame, text="作者: LXX", 
                 font=('黑体', 12)).pack()
        
        # 机器码显示
        machine_frame = ttk.LabelFrame(self.root, text="机器码", padding="10")
        machine_frame.pack(fill='x', padx=10, pady=5)
        
        self.machine_id = self.generate_machine_id()
        machine_text = ttk.Entry(machine_frame, width=40)
        machine_text.insert(0, self.machine_id)
        machine_text.configure(state='readonly')
        machine_text.pack()
        
        # 授权码输入
        auth_frame = ttk.LabelFrame(self.root, text="授权码", padding="10")
        auth_frame.pack(fill='x', padx=10, pady=5)
        
        self.auth_entry = ttk.Entry(auth_frame, width=40)
        self.auth_entry.pack()
        
        # 验证按钮
        btn_frame = ttk.Frame(self.root, padding="10")
        btn_frame.pack(fill='x')
        
        ttk.Button(btn_frame, text="验证授权", 
                  command=self.verify_auth).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="退出", 
                  command=self.root.quit).pack(side='left', padx=5)
        
        # 联系信息
        contact_frame = ttk.Frame(self.root, padding="10")
        contact_frame.pack(fill='both', expand=True)
        
        ttk.Label(contact_frame, 
                 text="如需授权，请联系作者 LXX 获取授权码",
                 wraplength=300).pack()
    
    def generate_machine_id(self):
        """生成机器码"""
        try:
            c = wmi.WMI()
            
            # 获取主板序列号
            board_id = c.Win32_BaseBoard()[0].SerialNumber.strip()
            
            # 获取CPU ID
            cpu_id = c.Win32_Processor()[0].ProcessorId.strip()
            
            # 获取硬盘序列号
            disk_id = c.Win32_DiskDrive()[0].SerialNumber.strip()
            
            # 组合并生成哈希
            machine_string = f"{board_id}_{cpu_id}_{disk_id}"
            return hashlib.md5(machine_string.encode()).hexdigest()
            
        except Exception as e:
            print(f"生成机器码时出错: {str(e)}")
            return "ERROR_GENERATING_MACHINE_ID"
    
    def verify_auth(self):
        """验证授权码"""
        auth_code = self.auth_entry.get().strip()
        
        # 计算正确的授权码
        auth_string = self.machine_id + "password123"
        correct_auth = hashlib.sha256(auth_string.encode()).hexdigest()[:16]
        
        if auth_code == correct_auth:
            # 保存授权信息
            auth_info = {
                'machine_id': self.machine_id,
                'auth_code': auth_code,
                'auth_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            try:
                with open('auth.json', 'w') as f:
                    json.dump(auth_info, f)
                
                messagebox.showinfo("成功", "授权验证成功！")
                self.root.destroy()
                
                # 启动主程序
                app = NetworkManager()
                app.run()
                
            except Exception as e:
                messagebox.showerror("错误", f"保存授权信息失败: {str(e)}")
        else:
            messagebox.showerror("错误", "授权码错误！请联系作者 LXX 获取正确的授权码。")
    
    def run(self):
        self.root.mainloop()

class NetworkManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("网卡 IP 管理工具 - 作者：LXX")  # 修改标题
        self.root.geometry("800x600")
        
        self.ip_config = IPConfig()
        self.setup_ui()
        
    def setup_ui(self):
        # 创建notebook用于分页
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # IP设置页面
        self.ip_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ip_frame, text='IP设置')
        
        # IP列表页面
        self.list_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.list_frame, text='IP列表')
        
        # 添加终端页面
        self.terminal_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_frame, text='终端')
        
        self.setup_ip_frame()
        self.setup_list_frame()
        self.setup_terminal_frame()
    
    def setup_ip_frame(self):
        # 网卡选择区域
        interface_frame = ttk.LabelFrame(self.ip_frame, text="网卡选择", padding=10)
        interface_frame.pack(fill='x', padx=5, pady=5)
        
        interfaces = get_network_interfaces()
        if not interfaces:
            print("Debug - No interfaces found")  # 调试信息
        else:
            print(f"Debug - Found interfaces: {interfaces}")  # 调试信息
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(interface_frame, 
                                          textvariable=self.interface_var,
                                          values=interfaces)
        self.interface_combo.pack(fill='x')
        if interfaces:
            self.interface_combo.set(interfaces[0])  # 设置默认值
        self.interface_combo.bind('<<ComboboxSelected>>', self.on_interface_select)
        
        # IP信息显示区域
        info_frame = ttk.LabelFrame(self.ip_frame, text="当前IP信息", padding=10)
        info_frame.pack(fill='x', padx=5, pady=5)
        
        self.current_ip_label = ttk.Label(info_frame, text="IP: ")
        self.current_ip_label.pack(fill='x')
        self.current_mask_label = ttk.Label(info_frame, text="掩码: ")
        self.current_mask_label.pack(fill='x')
        self.current_gateway_label = ttk.Label(info_frame, text="网关: ")
        self.current_gateway_label.pack(fill='x')
        
        # IP设置区域
        setting_frame = ttk.LabelFrame(self.ip_frame, text="IP设置", padding=10)
        setting_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(setting_frame, text="IP地址:").pack(fill='x')
        self.ip_entry = ttk.Entry(setting_frame)
        self.ip_entry.pack(fill='x')
        
        ttk.Label(setting_frame, text="子网掩码:").pack(fill='x')
        self.mask_entry = ttk.Entry(setting_frame)
        self.mask_entry.pack(fill='x')
        
        ttk.Label(setting_frame, text="网关:").pack(fill='x')
        self.gateway_entry = ttk.Entry(setting_frame)
        self.gateway_entry.pack(fill='x')
        
        ttk.Label(setting_frame, text="DNS:").pack(fill='x')
        self.dns_entry = ttk.Entry(setting_frame)
        self.dns_entry.pack(fill='x')
        
        # 在IP设置区域添加一个下拉列表用于快速选择保存的配置
        saved_frame = ttk.LabelFrame(self.ip_frame, text="保存的配置", padding=10)
        saved_frame.pack(fill='x', padx=5, pady=5)
        
        self.saved_config_var = tk.StringVar()
        self.saved_config_combo = ttk.Combobox(saved_frame, 
                                         textvariable=self.saved_config_var,
                                         state='readonly')
        self.saved_config_combo.pack(fill='x')
        self.saved_config_combo.bind('<<ComboboxSelected>>', self.on_saved_config_select)
        
        # 按钮区域
        button_frame = ttk.Frame(self.ip_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(button_frame, text="应用设置", 
                  command=self.apply_settings).pack(side='left', padx=5)
        ttk.Button(button_frame, text="保存到列表", 
                  command=self.save_to_list).pack(side='left', padx=5)
        ttk.Button(button_frame, text="恢复DHCP", 
                  command=self.restore_dhcp).pack(side='left', padx=5)

    def setup_list_frame(self):
        # 创建工具栏框架
        toolbar_frame = ttk.Frame(self.list_frame)
        toolbar_frame.pack(fill='x', padx=5, pady=5)
        
        # 添加新增按钮
        self.add_btn = ttk.Button(toolbar_frame, text="新增", command=self.add_new_config)
        self.add_btn.pack(side='left', padx=5)
        
        # 添加删除按钮
        self.delete_btn = ttk.Button(toolbar_frame, text="删除选中", command=self.delete_selected)
        self.delete_btn.pack(side='left', padx=5)
        
        # 创建Treeview来显示IP列表
        columns = ('alias', 'interface', 'ip', 'mask', 'gateway', 'dns')
        self.ip_tree = ttk.Treeview(self.list_frame, columns=columns, show='headings', selectmode='browse')
        
        # 设置列标题
        self.ip_tree.heading('alias', text='别名')
        self.ip_tree.heading('interface', text='网卡')
        self.ip_tree.heading('ip', text='IP地址')
        self.ip_tree.heading('mask', text='子网掩码')
        self.ip_tree.heading('gateway', text='网关')
        self.ip_tree.heading('dns', text='DNS')
        
        # 设置列宽
        for col in columns:
            self.ip_tree.column(col, width=100)
        
        # 创建滚动条
        scrollbar = ttk.Scrollbar(self.list_frame, orient='vertical', command=self.ip_tree.yview)
        
        # 使用网格布局来组织Treeview和滚动条
        self.ip_tree.pack(fill='both', expand=True, padx=5, pady=5)
        scrollbar.pack(side='right', fill='y')
        
        self.ip_tree.configure(yscrollcommand=scrollbar.set)
        
        # 绑定双击和选择事件
        self.ip_tree.bind('<Double-1>', self.on_item_double_click)
        self.ip_tree.bind('<<TreeviewSelect>>', self.on_item_select)
        
        # 刷新IP列表
        self.refresh_ip_list()

    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def apply_settings(self):
        try:
            interface = self.interface_var.get()
            ip = self.ip_entry.get()
            mask = self.mask_entry.get()
            gateway = self.gateway_entry.get()
            dns = self.dns_entry.get()
            
            print(f"Debug - 应用设置: {interface}, {ip}, {mask}, {gateway}, {dns}")  # 调试信息
            
            if not all([interface, ip, mask, gateway]):
                messagebox.showerror("错误", "请填写所有必要信息")
                return
            
            if not all(self.validate_ip(addr) for addr in [ip, gateway] if addr):
                messagebox.showerror("错误", "IP地址格式不正确")
                return
            
            update_ip(interface, ip, mask, gateway, dns if dns else None)
            messagebox.showinfo("成功", "网络设置已更新")
            
            # 更新当前IP信息显示
            self.on_interface_select(None)
            
        except Exception as e:
            print(f"Debug - 应用设置时出错: {str(e)}")  # 调试信息
            messagebox.showerror("错误", f"更新失败: {str(e)}")

    def save_to_list(self):
        try:
            # 获取当前设置
            interface = self.interface_var.get()
            ip = self.ip_entry.get()
            mask = self.mask_entry.get()
            gateway = self.gateway_entry.get()
            dns = self.dns_entry.get()
            
            # 验证必要字段
            if not all([interface, ip, mask, gateway]):
                messagebox.showerror("错误", "请填写所有必要信息")
                return
            
            # 请求别名
            alias = simpledialog.askstring("别名", "请为此配置输入别名：")
            if alias:
                # 保存配置
                self.ip_config.add_ip_config(
                    alias,
                    interface,
                    ip,
                    mask,
                    gateway,
                    dns if dns else ""  # 如果DNS为空，保存空字符串而不是None
                )
                # 刷新列表
                self.refresh_ip_list()
                print(f"Debug - 已保存配置: {alias}, {interface}, {ip}, {mask}, {gateway}, {dns}")
        except Exception as e:
            print(f"Debug - 保存配置时出错: {str(e)}")
            messagebox.showerror("错误", f"保存配置失败: {str(e)}")

    def refresh_ip_list(self):
        """刷新IP列表和保存的配置下拉列表"""
        # 清空现有项目
        for item in self.ip_tree.get_children():
            self.ip_tree.delete(item)
        
        # 添加所有配置
        for config in self.ip_config.get_all_configs():
            self.ip_tree.insert('', 'end', values=(
                config['alias'],
                config['interface'],
                config['ip'],
                config['mask'],
                config['gateway'],
                config['dns']
            ))
        
        # 刷新保存的配置下拉列表
        self.refresh_saved_configs()

    def on_item_double_click(self, event):
        try:
            # 获取选中的项目
            selection = self.ip_tree.selection()
            if not selection:
                return
            
            item = selection[0]
            config = self.ip_tree.item(item)['values']
            
            if not config:
                return
            
            print(f"Debug - 选中的配置: {config}")  # 调试信息
            
            # 更新网卡选择
            interface = config[1]
            if interface in self.interface_combo['values']:
                self.interface_var.set(interface)
                # 触发网卡选择事件，更新当前IP信息显示
                self.on_interface_select(None)
            
            # 更新输入框
            entries = [
                (self.ip_entry, config[2]),      # IP地址
                (self.mask_entry, config[3]),     # 子网掩码
                (self.gateway_entry, config[4]),  # 网关
                (self.dns_entry, config[5])       # DNS
            ]
            
            # 清空并填充所有输入框
            for entry, value in entries:
                entry.delete(0, tk.END)
                if value and value != 'None':  # 确保值不是None或'None'字符串
                    entry.insert(0, value)
            
            # 切换到IP设置页面
            self.notebook.select(0)
            
            print("Debug - IP配置已加载到设置界面")  # 调试信息
            
        except Exception as e:
            print(f"Debug - 加载IP配置时出错: {str(e)}")  # 调试信息
            messagebox.showerror("错误", f"加载配置失败: {str(e)}")

    def restore_dhcp(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("错误", "请选择网卡")
            return
            
        try:
            # 使用ipv4命令
            cmd = f'netsh interface ipv4 set address name="{interface}" dhcp'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='gbk')
            if result.returncode != 0:
                raise Exception(result.stderr if result.stderr else result.stdout)
            
            dns_cmd = f'netsh interface ipv4 set dns name="{interface}" dhcp'
            dns_result = subprocess.run(dns_cmd, shell=True, capture_output=True, text=True, encoding='gbk')
            if dns_result.returncode != 0:
                raise Exception(dns_result.stderr if dns_result.stderr else dns_result.stdout)
            
            messagebox.showinfo("成功", "已恢复DHCP设置")
        except Exception as e:
            error_msg = f"恢复DHCP失败: {str(e)}"
            print(f"Debug - {error_msg}")
            messagebox.showerror("错误", error_msg)

    def on_interface_select(self, event):
        """当选择网卡时更新显示的IP信息"""
        selected_interface = self.interface_var.get()
        if selected_interface:
            try:
                ip_details = get_ip_details(selected_interface)
                print(f"获取到的IP详情: {ip_details}")  # 调试信息
                
                # 更新显示标签
                self.current_ip_label.config(text=f"IP: {ip_details.get('IP', 'N/A')}")
                self.current_mask_label.config(text=f"掩码: {ip_details.get('Mask', 'N/A')}")
                self.current_gateway_label.config(text=f"网关: {ip_details.get('Gateway', 'N/A')}")
                
                # 自动填充当前设置到输入框
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, ip_details.get('IP', ''))
                self.mask_entry.delete(0, tk.END)
                self.mask_entry.insert(0, ip_details.get('Mask', ''))
                self.gateway_entry.delete(0, tk.END)
                self.gateway_entry.insert(0, ip_details.get('Gateway', ''))
            except Exception as e:
                print(f"更新IP信息时出错: {str(e)}")  # 调试信息
                messagebox.showerror("错误", f"获取网卡信息失败: {str(e)}")

    def delete_selected(self):
        """删除选中的配置"""
        selection = self.ip_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要删除的配置")
            return
        
        if messagebox.askyesno("确认", "确定要删除选中的配置吗？"):
            try:
                # 获取选中项的索引
                item = selection[0]
                index = self.ip_tree.index(item)
                # 从配置文件中删除
                self.ip_config.remove_ip_config(index)
                # 刷新列表
                self.refresh_ip_list()
                messagebox.showinfo("成功", "配置已删除")
            except Exception as e:
                messagebox.showerror("错误", f"删除配置失败: {str(e)}")

    def on_item_select(self, event):
        """当选择列表项时触发"""
        selection = self.ip_tree.selection()
        if selection:
            # 获取选中项的值
            item = selection[0]
            config = self.ip_tree.item(item)['values']
            if config:
                print(f"Debug - 选中配置: {config}")  # 调试信息

    def refresh_saved_configs(self):
        """刷新保存的配置下拉列表"""
        configs = self.ip_config.get_all_configs()
        options = [f"{config['alias']} ({config['ip']})" for config in configs]
        self.saved_config_combo['values'] = options
        if options:
            self.saved_config_combo.set(options[0])

    def on_saved_config_select(self, event):
        """当选择保存的配置时触发"""
        selected = self.saved_config_combo.get()
        if selected:
            # 从选项中提取别名
            alias = selected.split(' (')[0]
            # 查找对应的配置
            configs = self.ip_config.get_all_configs()
            for config in configs:
                if config['alias'] == alias:
                    # 填充配置到输入框
                    self.ip_entry.delete(0, tk.END)
                    self.ip_entry.insert(0, config['ip'])
                    self.mask_entry.delete(0, tk.END)
                    self.mask_entry.insert(0, config['mask'])
                    self.gateway_entry.delete(0, tk.END)
                    self.gateway_entry.insert(0, config['gateway'])
                    self.dns_entry.delete(0, tk.END)
                    self.dns_entry.insert(0, config['dns'])
                    break

    def add_new_config(self):
        """添加新的IP配置"""
        # 创建新窗口
        dialog = tk.Toplevel(self.root)
        dialog.title("新增IP配置")
        dialog.geometry("400x500")
        
        # 使窗口模态
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 创建输入框架
        frame = ttk.Frame(dialog, padding="10")
        frame.pack(fill='both', expand=True)
        
        # 别名输入
        ttk.Label(frame, text="别名:").pack(fill='x', pady=2)
        alias_entry = ttk.Entry(frame)
        alias_entry.pack(fill='x', pady=2)
        
        # 网卡选择
        ttk.Label(frame, text="网卡:").pack(fill='x', pady=2)
        interface_var = tk.StringVar()
        interface_combo = ttk.Combobox(frame, textvariable=interface_var, values=self.interface_combo['values'])
        interface_combo.pack(fill='x', pady=2)
        
        # IP地址输入
        ttk.Label(frame, text="IP地址:").pack(fill='x', pady=2)
        ip_entry = ttk.Entry(frame)
        ip_entry.pack(fill='x', pady=2)
        
        # 子网掩码输入
        ttk.Label(frame, text="子网掩码:").pack(fill='x', pady=2)
        mask_entry = ttk.Entry(frame)
        mask_entry.pack(fill='x', pady=2)
        
        # 网关输入
        ttk.Label(frame, text="网关:").pack(fill='x', pady=2)
        gateway_entry = ttk.Entry(frame)
        gateway_entry.pack(fill='x', pady=2)
        
        # DNS输入
        ttk.Label(frame, text="DNS:").pack(fill='x', pady=2)
        dns_entry = ttk.Entry(frame)
        dns_entry.pack(fill='x', pady=2)
        
        def validate_and_save():
            # 获取输入值
            alias = alias_entry.get().strip()
            interface = interface_var.get().strip()
            ip = ip_entry.get().strip()
            mask = mask_entry.get().strip()
            gateway = gateway_entry.get().strip()
            dns = dns_entry.get().strip()
            
            # 验证必填字段
            if not all([alias, interface, ip, mask, gateway]):
                messagebox.showerror("错误", "请填写所有必要信息（DNS可选）", parent=dialog)
                return
            
            # 验证IP地址格式
            if not all(self.validate_ip(addr) for addr in [ip, gateway] if addr):
                messagebox.showerror("错误", "IP地址格式不正确", parent=dialog)
                return
            
            try:
                # 保存配置
                self.ip_config.add_ip_config(
                    alias,
                    interface,
                    ip,
                    mask,
                    gateway,
                    dns
                )
                # 刷新列表
                self.refresh_ip_list()
                messagebox.showinfo("成功", "配置已保存", parent=dialog)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {str(e)}", parent=dialog)
        
        # 按钮区域
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill='x', pady=10)
        
        ttk.Button(btn_frame, text="保存", command=validate_and_save).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side='left', padx=5)
        
        # 设置默认值
        if self.interface_combo['values']:
            interface_combo.set(self.interface_combo['values'][0])
        mask_entry.insert(0, "255.255.255.0")  # 设置默认子网掩码

    def setup_terminal_frame(self):
        """设置终端界面"""
        # 创建一个框架来包含所有内容
        main_frame = ttk.Frame(self.terminal_frame)
        main_frame.pack(fill='both', expand=True)
        
        # 创建左侧工具面板，使用Canvas和Scrollbar实现滚动
        tools_canvas = tk.Canvas(main_frame, width=300)
        tools_canvas.pack(side='left', fill='y', padx=5, pady=5)
        
        # 添加滚动条
        tools_scrollbar = ttk.Scrollbar(main_frame, orient='vertical', command=tools_canvas.yview)
        tools_scrollbar.pack(side='left', fill='y')
        
        # 配置Canvas
        tools_canvas.configure(yscrollcommand=tools_scrollbar.set)
        
        # 创建工具框架
        tools_frame = ttk.Frame(tools_canvas)
        tools_canvas.create_window((0, 0), window=tools_frame, anchor='nw', width=tools_canvas.winfo_reqwidth())
        
        # 绑定调整大小事件
        def on_configure(event):
            tools_canvas.configure(scrollregion=tools_canvas.bbox('all'))
        tools_frame.bind('<Configure>', on_configure)
        
        # === 路由配置部分 ===
        route_frame = ttk.LabelFrame(tools_frame, text="路由配置", padding=5)
        route_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(route_frame, text="目标网络:").pack(fill='x')
        self.route_dest = ttk.Entry(route_frame)
        self.route_dest.pack(fill='x', pady=2)
        
        ttk.Label(route_frame, text="子网掩码:").pack(fill='x')
        self.route_mask = ttk.Entry(route_frame)
        self.route_mask.pack(fill='x', pady=2)
        self.route_mask.insert(0, "255.255.255.0")
        
        ttk.Label(route_frame, text="下一跳:").pack(fill='x')
        self.route_gateway = ttk.Entry(route_frame)
        self.route_gateway.pack(fill='x', pady=2)
        
        ttk.Button(route_frame, text="添加路由", 
                   command=self.add_route).pack(fill='x', pady=2)
        ttk.Button(route_frame, text="删除路由", 
                   command=self.delete_route).pack(fill='x', pady=2)
        
        # 添加路由表显示区域
        self.route_table = ttk.Treeview(route_frame, columns=('dest', 'mask', 'gateway', 'interface', 'metric'),
                                       show='headings', height=5)
        self.route_table.heading('dest', text='目标网络')
        self.route_table.heading('mask', text='子网掩码')
        self.route_table.heading('gateway', text='网关')
        self.route_table.heading('interface', text='接口')
        self.route_table.heading('metric', text='跃点数')
        
        # 设置列宽
        for col in ('dest', 'mask', 'gateway', 'interface', 'metric'):
            self.route_table.column(col, width=100)
        
        self.route_table.pack(fill='x', pady=2)
        
        # 添加刷新按钮
        ttk.Button(route_frame, text="刷新路由表", 
                   command=self.refresh_route_table).pack(fill='x', pady=2)
        
        # === Ping工具部分 ===
        ping_frame = ttk.LabelFrame(tools_frame, text="Ping工具", padding=5)
        ping_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(ping_frame, text="目标地址:").pack(fill='x')
        self.ping_dest = ttk.Entry(ping_frame)
        self.ping_dest.pack(fill='x', pady=2)
        
        ttk.Label(ping_frame, text="源地址(可选):").pack(fill='x')
        self.ping_source = ttk.Entry(ping_frame)
        self.ping_source.pack(fill='x', pady=2)
        
        # 添加包大小和超时设置
        size_frame = ttk.Frame(ping_frame)
        size_frame.pack(fill='x', pady=2)
        
        ttk.Label(size_frame, text="包大小:").pack(side='left')
        self.ping_size = ttk.Entry(size_frame, width=8)
        self.ping_size.pack(side='left', padx=2)
        
        ttk.Label(size_frame, text="超时(ms):").pack(side='left', padx=2)
        self.ping_timeout = ttk.Entry(size_frame, width=8)
        self.ping_timeout.pack(side='left', padx=2)
        
        # IP版本选择
        self.ping_ip_version = tk.StringVar(value="IPv4")
        ttk.Radiobutton(ping_frame, text="IPv4", 
                        variable=self.ping_ip_version, value="IPv4").pack(side='left')
        ttk.Radiobutton(ping_frame, text="IPv6", 
                        variable=self.ping_ip_version, value="IPv6").pack(side='left')
        
        # Ping按钮框架
        ping_btn_frame = ttk.Frame(ping_frame)
        ping_btn_frame.pack(fill='x', pady=2)
        
        self.start_ping_btn = ttk.Button(ping_btn_frame, text="开始Ping", 
                                        command=self.start_ping)
        self.start_ping_btn.pack(side='left', fill='x', expand=True, padx=2)
        
        self.stop_ping_btn = ttk.Button(ping_btn_frame, text="停止", 
                                       command=self.stop_command, state='disabled')
        self.stop_ping_btn.pack(side='left', fill='x', expand=True, padx=2)
        
        # === Tracert工具部分 ===
        tracert_frame = ttk.LabelFrame(tools_frame, text="路由跟踪", padding=5)
        tracert_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(tracert_frame, text="目标地址:").pack(fill='x')
        self.tracert_dest = ttk.Entry(tracert_frame)
        self.tracert_dest.pack(fill='x', pady=2)
        
        # IP版本选择
        self.tracert_ip_version = tk.StringVar(value="IPv4")
        ttk.Radiobutton(tracert_frame, text="IPv4", 
                        variable=self.tracert_ip_version, value="IPv4").pack(side='left')
        ttk.Radiobutton(tracert_frame, text="IPv6", 
                        variable=self.tracert_ip_version, value="IPv6").pack(side='left')
        
        # 在Tracert工具部分添加停止按钮
        tracert_btn_frame = ttk.Frame(tracert_frame)
        tracert_btn_frame.pack(fill='x', pady=2)
        
        self.start_tracert_btn = ttk.Button(tracert_btn_frame, text="开始跟踪", 
                                           command=self.start_tracert)
        self.start_tracert_btn.pack(side='left', fill='x', expand=True, padx=2)
        
        self.stop_tracert_btn = ttk.Button(tracert_btn_frame, text="停止", 
                                          command=self.stop_command, state='disabled')
        self.stop_tracert_btn.pack(side='left', fill='x', expand=True, padx=2)
        
        # === 网络测试部分 ===
        test_frame = ttk.LabelFrame(tools_frame, text="网络测试", padding=5)
        test_frame.pack(fill='x', padx=5, pady=5)
        
        # DNS测试
        ttk.Button(test_frame, text="DNS解析测试", 
                   command=lambda: self.quick_execute("nslookup www.baidu.com")).pack(fill='x', pady=2)
        
        # TCP端口测试
        port_frame = ttk.Frame(test_frame)
        port_frame.pack(fill='x', pady=2)
        
        ttk.Label(port_frame, text="目标:").pack(side='left')
        self.port_host = ttk.Entry(port_frame)
        self.port_host.pack(side='left', fill='x', expand=True, padx=2)
        
        ttk.Label(port_frame, text="端口:").pack(side='left', padx=2)
        self.port_number = ttk.Entry(port_frame, width=8)
        self.port_number.pack(side='left', padx=2)
        
        ttk.Button(test_frame, text="端口测试", 
                   command=self.test_port).pack(fill='x', pady=2)

        # === 终端输出部分 ===
        terminal_frame = ttk.Frame(main_frame)
        terminal_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        # 终端输出区域
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            background='black',
            foreground='white',
            font=('Consolas', 10)
        )
        self.terminal_output.pack(fill='both', expand=True)
        
        # 命令输入区域
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill='x', pady=5)
        
        ttk.Label(input_frame, text="命令:").pack(side='left', padx=5)
        self.cmd_entry = ttk.Entry(input_frame)
        self.cmd_entry.pack(side='left', fill='x', expand=True, padx=5)
        self.cmd_entry.bind('<Return>', self.execute_command)
        
        ttk.Button(input_frame, text="执行", 
                   command=lambda: self.execute_command(None)).pack(side='left', padx=2)
        ttk.Button(input_frame, text="清空", 
                   command=self.clear_terminal).pack(side='left', padx=2)
        
        # 初始化命令队列和输出队列
        self.cmd_queue = queue.Queue()
        self.output_queue = queue.Queue()
        
        # 启动命令处理线程
        self.cmd_thread = threading.Thread(target=self.process_commands, daemon=True)
        self.cmd_thread.start()
        
        # 启动输出更新
        self.update_terminal_output()
        
        # 绑定鼠标滚轮事件
        def on_mousewheel(event):
            tools_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        tools_canvas.bind_all("<MouseWheel>", on_mousewheel)

    def execute_command(self, event):
        """执行命令"""
        command = self.cmd_entry.get().strip()
        if command:
            self.cmd_entry.delete(0, tk.END)
            self.terminal_output.insert(tk.END, f"\n> {command}\n")
            self.terminal_output.see(tk.END)
            self.cmd_queue.put(command)
    
    def quick_execute(self, command):
        """快速执行预设命令"""
        self.terminal_output.insert(tk.END, f"\n> {command}\n")
        self.terminal_output.see(tk.END)
        self.cmd_queue.put(command)
    
    def clear_terminal(self):
        """清空终端输出"""
        self.terminal_output.delete(1.0, tk.END)
    
    def process_commands(self):
        """处理命令队列"""
        while True:
            try:
                command = self.cmd_queue.get()
                try:
                    # 执行命令并获取输出
                    self.current_process = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        encoding='gbk'
                    )
                    
                    # 读取输出
                    while True:
                        if self.current_process is None:  # 检查是否被停止
                            break
                        
                        output = self.current_process.stdout.readline()
                        if output:
                            self.output_queue.put(output)
                        elif self.current_process.poll() is not None:
                            break
                    
                    # 读取错误输出
                    if self.current_process and self.current_process.stderr:
                        stderr = self.current_process.stderr.read()
                        if stderr:
                            self.output_queue.put(f"错误: {stderr}\n")
                    
                    # 命令完成后恢复按钮状态
                    self.root.after(0, self.reset_buttons)
                    
                except Exception as e:
                    self.output_queue.put(f"执行出错: {str(e)}\n")
                    self.root.after(0, self.reset_buttons)
                    
            except queue.Empty:
                continue
    
    def update_terminal_output(self):
        """更新终端输出"""
        try:
            while True:
                try:
                    # 非阻塞方式获取输出
                    output = self.output_queue.get_nowait()
                    self.terminal_output.insert(tk.END, output)
                    self.terminal_output.see(tk.END)
                except queue.Empty:
                    break
        except:
            pass
        finally:
            # 每100ms更新一次
            self.root.after(100, self.update_terminal_output)

    def add_route(self):
        """添加路由"""
        dest = self.route_dest.get().strip()
        mask = self.route_mask.get().strip()
        gateway = self.route_gateway.get().strip()
        
        if not all([dest, mask, gateway]):
            messagebox.showerror("错误", "请填写所有路由信息")
            return
        
        command = f'route add {dest} mask {mask} {gateway}'
        self.quick_execute(command)

    def delete_route(self):
        """删除路由"""
        dest = self.route_dest.get().strip()
        if not dest:
            messagebox.showerror("错误", "请输入要删除的目标网络")
            return
        
        command = f'route delete {dest}'
        self.quick_execute(command)

    def start_ping(self):
        """开始ping"""
        dest = self.ping_dest.get().strip()
        source = self.ping_source.get().strip()
        version = self.ping_ip_version.get()
        
        if not dest:
            messagebox.showerror("错误", "请输入目标地址")
            return
        
        command = 'ping '
        if version == "IPv6":
            command = 'ping -6 '
        
        if source:
            command += f'-S {source} '
        
        command += f'{dest} -t'  # 添加 -t 参数使ping持续运行
        
        # 添加额外参数
        size = self.ping_size.get().strip()
        timeout = self.ping_timeout.get().strip()
        
        if size:
            command += f' -l {size}'
        if timeout:
            command += f' -w {timeout}'
        
        # 禁用开始按钮，启用停止按钮
        self.start_ping_btn.config(state='disabled')
        self.stop_ping_btn.config(state='normal')
        self.start_tracert_btn.config(state='disabled')
        
        print(f"Debug - 执行Ping命令: {command}")  # 调试信息
        self.quick_execute(command)

    def start_tracert(self):
        """开始路由跟踪"""
        dest = self.tracert_dest.get().strip()
        version = self.tracert_ip_version.get()
        
        if not dest:
            messagebox.showerror("错误", "请输入目标地址")
            return
        
        command = 'tracert '
        if version == "IPv6":
            command = 'tracert -6 '
        
        command += dest
        
        # 禁用开始按钮，启用停止按钮
        self.start_tracert_btn.config(state='disabled')
        self.stop_tracert_btn.config(state='normal')
        self.start_ping_btn.config(state='disabled')
        
        self.quick_execute(command)

    def stop_command(self):
        """停止当前命令执行"""
        if hasattr(self, 'current_process') and self.current_process:
            try:
                # 在Windows上使用taskkill强制终止进程树
                subprocess.run(f'taskkill /F /T /PID {self.current_process.pid}', 
                             shell=True, capture_output=True)
                self.current_process = None
                
                # 恢复按钮状态
                self.reset_buttons()
                
                self.terminal_output.insert(tk.END, "\n命令已停止\n")
                self.terminal_output.see(tk.END)
            except Exception as e:
                print(f"停止命令时出错: {str(e)}")

    def reset_buttons(self):
        """重置按钮状态"""
        self.start_ping_btn.config(state='normal')
        self.stop_ping_btn.config(state='disabled')
        self.start_tracert_btn.config(state='normal')
        self.stop_tracert_btn.config(state='disabled')

    def refresh_route_table(self):
        """刷新路由表显示"""
        try:
            # 清空现有项目
            for item in self.route_table.get_children():
                self.route_table.delete(item)
            
            # 获取路由表信息
            output = subprocess.check_output('route print -4', shell=True).decode('gbk')
            lines = output.split('\n')
            
            # 查找活动路由部分
            start_index = -1
            for i, line in enumerate(lines):
                if "活动路由:" in line:
                    start_index = i + 3  # 跳过表头
                    break
            
            if start_index > 0:
                # 解析路由条目
                for line in lines[start_index:]:
                    line = line.strip()
                    if not line:
                        break
                    
                    parts = line.split()
                    if len(parts) >= 4:
                        self.route_table.insert('', 'end', values=parts[:5])
            
        except Exception as e:
            print(f"刷新路由表时出错: {str(e)}")

    def test_port(self):
        """测试TCP端口连接"""
        host = self.port_host.get().strip()
        port = self.port_number.get().strip()
        
        if not host or not port:
            messagebox.showerror("错误", "请输入目标主机和端口")
            return
        
        try:
            port = int(port)
            # 使用telnet命令测试端口
            command = f"telnet {host} {port}"
            self.quick_execute(command)
        except ValueError:
            messagebox.showerror("错误", "端口必须是数字")

    def run(self):
        self.root.mainloop()

def check_auth():
    """检查授权状态"""
    try:
        # 检查授权文件是否存在
        if not os.path.exists('auth.json'):
            return False
        
        with open('auth.json', 'r') as f:
            auth_info = json.load(f)
        
        # 生成当前机器码
        c = wmi.WMI()
        board_id = c.Win32_BaseBoard()[0].SerialNumber.strip()
        cpu_id = c.Win32_Processor()[0].ProcessorId.strip()
        disk_id = c.Win32_DiskDrive()[0].SerialNumber.strip()
        machine_string = f"{board_id}_{cpu_id}_{disk_id}"
        current_machine_id = hashlib.md5(machine_string.encode()).hexdigest()
        
        # 验证机器码是否匹配
        if current_machine_id != auth_info['machine_id']:
            return False
        
        # 验证授权码是否正确
        auth_string = current_machine_id + "password123"
        correct_auth = hashlib.sha256(auth_string.encode()).hexdigest()[:16]
        
        return auth_info['auth_code'] == correct_auth
        
    except Exception as e:
        print(f"检查授权时出错: {str(e)}")
        return False

if __name__ == "__main__":
    if check_auth():
        app = NetworkManager()
        app.run()
    else:
        auth_window = AuthWindow()
        auth_window.run()
