from chaos_kitten.brain.cors import analyze_cors

def test_cors_wildcard_origin():
    headers = {
        "access-control-allow-origin": "*"
    }

    results = analyze_cors(headers)
    assert any(r["issue"] == "Wildcard ACAO" for r in results)


def test_cors_credentials_exposure():
    headers = {
        "access-control-allow-origin": "https://evil.example",
        "access-control-allow-credentials": "true"
    }

    results = analyze_cors(headers)
    assert any(r["severity"] == "critical" for r in results)