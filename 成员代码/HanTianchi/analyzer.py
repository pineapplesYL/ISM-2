import ast
import os
from typing import List, Dict, Any, Optional
from code_security_analyzer.utils import patterns, report

class SecurityAnalyzer:
    
    def __init__(self):
        self.vulnerabilities = []
        self.rules = patterns.get_security_rules()
    
    def analyze_file(self, filepath: str) -> List[Dict[str, Any]]:
        """分析单个文件中的安全问题"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                code = f.read()
            
            return self.analyze_code(code, filepath)
        except Exception as e:
            return [{"type": "error", "message": f"分析文件时出错: {str(e)}", "file": filepath}]
    
    def analyze_code(self, code: str, filename: Optional[str] = None) -> List[Dict[str, Any]]:
        """分析代码字符串中的安全问题"""
        self.vulnerabilities = []
        
        try:
            tree = ast.parse(code)
            self._analyze_ast(tree, filename or "代码片段")
            return self.vulnerabilities
        except SyntaxError as e:
            return [{"type": "error", "message": f"Python语法错误: {str(e)}", "file": filename}]
    
    def analyze_directory(self, directory: str) -> List[Dict[str, Any]]:
        """分析整个目录中的Python文件"""
        all_vulnerabilities = []
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    all_vulnerabilities.extend(self.analyze_file(filepath))
        
        return all_vulnerabilities
    
    def _analyze_ast(self, tree: ast.AST, filename: str) -> None:
        # 检查导入的危险模块
        self._check_dangerous_imports(tree, filename)
        
        # 检查SQL注入漏洞
        self._check_sql_injection(tree, filename)
        
        # 检查命令注入漏洞
        self._check_command_injection(tree, filename)
        
        # 检查不安全的反序列化
        self._check_unsafe_deserialization(tree, filename)
        
        # 检查硬编码的敏感信息
        self._check_hardcoded_secrets(tree, filename)
    
    def _check_dangerous_imports(self, tree: ast.AST, filename: str) -> None:
        """检查危险模块导入"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    if name.name in self.rules["dangerous_imports"]:
                        self.vulnerabilities.append({
                            "type": "dangerous_import",
                            "message": f"发现危险模块导入: {name.name}",
                            "file": filename,
                            "line": node.lineno
                        })
            elif isinstance(node, ast.ImportFrom):
                if node.module in self.rules["dangerous_imports"]:
                    self.vulnerabilities.append({
                        "type": "dangerous_import",
                        "message": f"发现危险模块导入: {node.module}",
                        "file": filename,
                        "line": node.lineno
                    })
    
    def _check_sql_injection(self, tree: ast.AST, filename: str) -> None:
        """检查SQL注入漏洞"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node, 'func') and isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.rules["sql_functions"]:
                        for arg in node.args:
                            # 检测所有字符串格式化方式
                            injection_patterns = (
                                ast.BinOp,        # 字符串拼接（+）
                                ast.JoinedStr,    # f-string
                                ast.Mod,          # % 格式化
                                ast.FormattedValue # format()方法
                            )
                        
                            def contains_unsafe(value):
                                """递归检测不安全节点"""
                                if isinstance(value, injection_patterns):
                                    return True
                                if isinstance(value, ast.BinOp):
                                    return any(contains_unsafe(operand) for operand in [value.left, value.right])
                                if hasattr(value, 'values'):
                                    return any(contains_unsafe(v) for v in value.values)
                                return False
                        
                            if contains_unsafe(arg):
                                self.vulnerabilities.append({
                                    "type": "sql_injection",
                                    "message": "可能的SQL注入漏洞: 使用动态字符串构建SQL查询",
                                    "file": filename,
                                    "line": node.lineno
                                })
    
    def _check_command_injection(self, tree: ast.AST, filename: str) -> None:
        """检查命令注入漏洞"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node, 'func') and isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in self.rules["command_execution_functions"]:
                        self.vulnerabilities.append({
                            "type": "command_injection",
                            "message": f"可能的命令注入漏洞: 使用{func_name}执行系统命令",
                            "file": filename,
                            "line": node.lineno
                        })
    
    def _check_unsafe_deserialization(self, tree: ast.AST, filename: str) -> None:
        """检查不安全的反序列化操作"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hasattr(node, 'func') and isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in self.rules["unsafe_deserialization_functions"]:
                        self.vulnerabilities.append({
                            "type": "unsafe_deserialization",
                            "message": f"不安全的反序列化: 使用{func_name}可能导致代码执行漏洞",
                            "file": filename,
                            "line": node.lineno
                        })
    
    def _check_hardcoded_secrets(self, tree: ast.AST, filename: str) -> None:
        """检查硬编码的敏感信息"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(secret_pattern in var_name for secret_pattern in self.rules["secret_patterns"]):
                            if isinstance(node.value, ast.Str) and len(node.value.s) > 3:
                                self.vulnerabilities.append({
                                    "type": "hardcoded_secret",
                                    "message": f"硬编码的敏感信息: 变量{target.id}可能包含密码或密钥",
                                    "file": filename,
                                    "line": node.lineno
                                })

def analyze(file_or_dir: str) -> List[Dict[str, Any]]:
    """分析文件或目录中的安全问题"""
    analyzer = SecurityAnalyzer()
    
    if os.path.isfile(file_or_dir):
        return analyzer.analyze_file(file_or_dir)
    elif os.path.isdir(file_or_dir):
        return analyzer.analyze_directory(file_or_dir)
    else:
        return [{"type": "error", "message": f"文件或目录不存在: {file_or_dir}"}] 
