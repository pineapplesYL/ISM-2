# tests/test_sql_injection.py 完整测试代码
import pytest
from analyzer import SecurityAnalyzer

@pytest.fixture
def analyzer():
    return SecurityAnalyzer()

def assert_sqli_detected(results, line_num):
    """自定义断言：验证指定行检测到SQL注入"""
    assert any(
        vuln["type"] == "sql_injection" 
        and vuln["line"] == line_num 
        and "动态字符串构建" in vuln["message"]
        for vuln in results
    ), f"第{line_num}行未正确检测到SQL注入漏洞"

# 基础测试用例
def test_sqli_string_concatenation(analyzer):
    code = """
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"  # 漏洞行
    cursor.execute(query)
    """
    assert_sqli_detected(analyzer.analyze_code(code), line_num=2)

def test_sqli_fstring(analyzer):
    code = """
    cursor.execute(f"SELECT * FROM users WHERE name = {user_input}")  # 漏洞行
    """
    assert_sqli_detected(analyzer.analyze_code(code), line_num=2)

# 参数化测试
@pytest.mark.parametrize("code_snippet, line", [
    ('''cursor.execute("WHERE id=%s" % data)''', 1),
    ('''conn.execute("VALUES {}".format(input))''', 1),
    ('''cur.executemany(f"INSERT {value}")''', 1)
])
def test_sqli_variants(analyzer, code_snippet, line):
    full_code = f"def test_func():\n    {code_snippet}"
    results = analyzer.analyze_code(full_code)
    assert_sqli_detected(results, line)

# 复杂场景测试
def test_nested_fstring(analyzer):
    code = """
    base = f"SELECT {','.join(fields)}"  # 漏洞行1
    query = f"{base} WHERE id={input}"   # 漏洞行2
    cursor.execute(query)               # 触发行
    """
    results = analyzer.analyze_code(code)
    assert_sqli_detected(results, line_num=2)  # 验证嵌套检测
    assert_sqli_detected(results, line_num=3)

# 反向测试（安全用法）
def test_parameterized_query(analyzer):
    code = '''
    # 安全用法示例
    cursor.execute(
        "SELECT * FROM users WHERE id = %s", 
        (user_id,)  # 参数化查询
    )
    '''
    assert len(analyzer.analyze_code(code)) == 0