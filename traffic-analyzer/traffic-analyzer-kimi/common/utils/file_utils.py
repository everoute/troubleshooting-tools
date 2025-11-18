"""文件操作工具模块"""

import os
from pathlib import Path
from typing import List, Union, Iterator, Optional


def find_files(directory: Union[str, Path], pattern: str = "*") -> List[Path]:
    """
    查找目录中的文件

    Args:
        directory: 目录路径
        pattern: 文件匹配模式（支持通配符）

    Returns:
        文件路径列表
    """
    dir_path = Path(directory)
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    return list(dir_path.glob(pattern))


def get_file_size(filepath: Union[str, Path]) -> int:
    """
    获取文件大小

    Args:
        filepath: 文件路径

    Returns:
        文件大小（字节）
    """
    return Path(filepath).stat().st_size


def ensure_dir(directory: Union[str, Path]) -> Path:
    """
    确保目录存在

    Args:
        directory: 目录路径

    Returns:
        目录路径对象
    """
    dir_path = Path(directory)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def read_file_lines(filepath: Union[str, Path], encoding: str = "utf-8") -> Iterator[str]:
    """
    逐行读取文件

    Args:
        filepath: 文件路径
        encoding: 文件编码

    Yields:
        每一行内容
    """
    with open(filepath, 'r', encoding=encoding) as f:
        for line in f:
            yield line.rstrip('\n\r')


def write_file_lines(filepath: Union[str, Path], lines: List[str],
                     encoding: str = "utf-8"):
    """
    写入多行到文件

    Args:
        filepath: 文件路径
        lines: 行内容列表
        encoding: 文件编码
    """
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding=encoding) as f:
        for line in lines:
            f.write(line + '\n')


def get_file_extension(filepath: Union[str, Path]) -> str:
    """
    获取文件扩展名

    Args:
        filepath: 文件路径

    Returns:
        扩展名（包含点号）
    """
    return Path(filepath).suffix


def get_file_stem(filepath: Union[str, Path]) -> str:
    """
    获取文件名（不含扩展名）

    Args:
        filepath: 文件路径

    Returns:
        文件名
    """
    return Path(filepath).stem


def check_file_exists(filepath: Union[str, Path]) -> bool:
    """
    检查文件是否存在

    Args:
        filepath: 文件路径

    Returns:
        是否存在
    """
    return Path(filepath).exists()
