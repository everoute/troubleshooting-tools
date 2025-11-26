"""配置管理模块"""

import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union


class Config:
    """配置管理类"""

    def __init__(self, config_path: Optional[str] = None):
        """
        初始化配置

        Args:
            config_path: 配置文件路径（可选）
        """
        if config_path:
            self.config = self._load_from_file(config_path)
        else:
            self.config = self._load_default()

    def _load_default(self) -> Dict[str, Any]:
        """加载默认配置"""
        return {
            "pcap": {
                "batch_size": 10000,
                "max_memory_mb": 1024,
                "tshark_path": "tshark",
                "tcp_last_retrans": 3,
                "retrans_threshold": 0.01
            },
            "tcpsocket": {
                "bandwidth_bps": 10000000000,  # 10Gbps default
                "r_threshold": 0.8,
                "t_threshold": 0.8,
                "w_threshold": 0.6
            },
            "report": {
                "text": {
                    "width": 80
                },
                "json": {
                    "indent": 2
                },
                "visual": {
                    "dpi": 300,
                    "format": "png"
                }
            }
        }

    def _load_from_file(self, filepath: str) -> Dict[str, Any]:
        """从文件加载配置"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        with open(filepath, 'r', encoding='utf-8') as f:
            if path.suffix.lower() in ['.yaml', '.yml']:
                return yaml.safe_load(f)
            elif path.suffix.lower() == '.json':
                return json.load(f)
            else:
                raise ValueError(f"Unsupported config format: {path.suffix}")

    def get(self, key: str, default=None) -> Any:
        """
        获取配置项

        Args:
            key: 配置键（支持点号分隔，如 'pcap.batch_size'）
            default: 默认值

        Returns:
            配置值
        """
        keys = key.split('.')
        value = self.config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any):
        """
        设置配置项

        Args:
            key: 配置键
            value: 配置值
        """
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def save(self, filepath: str):
        """
        保存配置到文件

        Args:
            filepath: 输出文件路径
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w', encoding='utf-8') as f:
            if path.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            elif path.suffix.lower() == '.json':
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            else:
                raise ValueError(f"Unsupported output format: {path.suffix}")


# 全局配置实例
_default_config = None


def get_config(config_path: Optional[str] = None) -> Config:
    """获取全局配置实例"""
    global _default_config
    if _default_config is None:
        _default_config = Config(config_path)
    return _default_config
