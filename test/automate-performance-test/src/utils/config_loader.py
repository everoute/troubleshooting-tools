#!/usr/bin/env python3
"""Configuration loader for YAML configs"""

import yaml
import os
import logging
from typing import Dict, Any


logger = logging.getLogger(__name__)


class ConfigLoader:
    """Configuration loader for YAML files"""

    def __init__(self, config_dir: str):
        """Initialize config loader

        Args:
            config_dir: Configuration directory path
        """
        self.config_dir = config_dir

    def load_ssh_config(self) -> Dict[str, Any]:
        """Load SSH configuration"""
        return self._load_yaml_file("ssh-config.yaml")

    def load_env_config(self) -> Dict[str, Any]:
        """Load environment configuration"""
        return self._load_yaml_file("test-env-config.yaml")

    def load_perf_spec(self) -> Dict[str, Any]:
        """Load performance test specifications"""
        return self._load_yaml_file("performance-test-spec.yaml")

    def load_ebpf_config(self) -> Dict[str, Any]:
        """Load eBPF tools configuration"""
        return self._load_yaml_file("ebpf-tools-config.yaml")

    def load_all_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load all configuration files

        Returns:
            Dictionary containing all configs
        """
        return {
            'ssh': self.load_ssh_config(),
            'env': self.load_env_config(),
            'perf': self.load_perf_spec(),
            'ebpf': self.load_ebpf_config()
        }

    def _load_yaml_file(self, filename: str) -> Dict[str, Any]:
        """Load YAML file

        Args:
            filename: YAML filename

        Returns:
            Parsed YAML content
        """
        filepath = os.path.join(self.config_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Config file not found: {filepath}")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                logger.info(f"Loaded config: {filename}")
                return content
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {filename}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error loading config file {filename}: {str(e)}")
            raise

    def validate_config(self, config_type: str, config: Dict[str, Any]) -> bool:
        """Validate configuration

        Args:
            config_type: Type of config (ssh/env/perf/ebpf)
            config: Configuration to validate

        Returns:
            Validation status
        """
        if config_type == 'ssh':
            return self._validate_ssh_config(config)
        elif config_type == 'env':
            return self._validate_env_config(config)
        elif config_type == 'perf':
            return self._validate_perf_config(config)
        elif config_type == 'ebpf':
            return self._validate_ebpf_config(config)
        else:
            logger.warning(f"Unknown config type: {config_type}")
            return False

    def _validate_ssh_config(self, config: Dict[str, Any]) -> bool:
        """Validate SSH configuration"""
        if 'ssh_hosts' not in config:
            return False

        for host_ref, host_config in config['ssh_hosts'].items():
            required_keys = ['host', 'user', 'workdir']
            if not all(key in host_config for key in required_keys):
                logger.error(f"Missing required keys in SSH config for {host_ref}")
                return False

        return True

    def _validate_env_config(self, config: Dict[str, Any]) -> bool:
        """Validate environment configuration"""
        if 'test_environments' not in config:
            return False

        for env_name, env_config in config['test_environments'].items():
            if 'server' not in env_config or 'client' not in env_config:
                logger.error(f"Missing server/client config for environment {env_name}")
                return False

        return True

    def _validate_perf_config(self, config: Dict[str, Any]) -> bool:
        """Validate performance test configuration"""
        if 'performance_tests' not in config:
            return False

        required_tests = ['throughput', 'latency', 'pps']
        for test_type in required_tests:
            if test_type not in config['performance_tests']:
                logger.error(f"Missing performance test type: {test_type}")
                return False

        return True

    def _validate_ebpf_config(self, config: Dict[str, Any]) -> bool:
        """Validate eBPF tools configuration"""
        if 'ebpf_tools' not in config:
            return False

        for tool_id, tool_config in config['ebpf_tools'].items():
            required_keys = ['id', 'name', 'testcase_source', 'test_associations']
            if not all(key in tool_config for key in required_keys):
                logger.error(f"Missing required keys in eBPF config for {tool_id}")
                return False

        return True