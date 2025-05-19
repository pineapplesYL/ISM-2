def test_sqli_fstring():
    code = """
    cursor.execute(f"SELECT * FROM users WHERE name = {user_input}")
    """
    vulnerabilities = analyzer.analyze_code(code)
    assert len(vulnerabilities) > 0  # 确认检测到漏洞
