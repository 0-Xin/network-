import json
import os

class IPConfig:
    def __init__(self):
        self.config_file = 'ip_settings.json'
        self.ip_list = self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_config(self):
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.ip_list, f, ensure_ascii=False, indent=2)

    def add_ip_config(self, alias, interface, ip, mask, gateway, dns):
        config = {
            'alias': alias,
            'interface': interface,
            'ip': ip,
            'mask': mask,
            'gateway': gateway,
            'dns': dns
        }
        self.ip_list.append(config)
        self.save_config()

    def remove_ip_config(self, index):
        if 0 <= index < len(self.ip_list):
            self.ip_list.pop(index)
            self.save_config()

    def get_all_configs(self):
        return self.ip_list 