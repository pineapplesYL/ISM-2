import pytest
from analyzer import SecurityAnalyzer

@pytest.fixture
def analyzer():
    return SecurityAnalyzer()

def test_sqli_string_concatenation(analyzer):
    code = """
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    """
    results = analyzer.analyze_code(code)
    assert any(vuln["type"] == "sql_injection" for vuln in results)

def test_sqli_fstring(analyzer):
    code = """
    cursor.execute(f"SELECT * FROM users WHERE name = {user_input}")
    """
    results = analyzer.analyze_code(code)
    assert len(results) > 0, "应检测到f-string格式的SQL注入"

def test_sqli_percent_format(analyzer):
    code = """
    cursor.execute("SELECT * FROM users WHERE name = %s" % user_input)
    """
    results = analyzer.analyze_code(code)
    assert any(vuln["line"] == 3 for vuln in results)

def test_sqli_format_method(analyzer):
    code = '''
    query = "SELECT * FROM users WHERE name = {}".format(untrusted_input)
    conn.executescript(query)
    '''
    vulnerabilities = analyzer.analyze_code(code)
    assert [v for v in vulnerabilities if v["type"] == "sql_injection"]