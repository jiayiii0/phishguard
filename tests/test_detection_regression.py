from backend.app.services.predictor import PhishGuardPredictor


LEGITIMATE_HARD_CASES = [
    "https://docs.google.com/forms/u/1/d/e/1FAIpQLSfmkF4oiWVWs_Kiu-5igwc_1iLbbF9itc0DpkLmT4OQTlWXcQ/formResponse",
    "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn",
    "https://github.com/login?return_to=%2Fsettings%2Fsecurity",
    "https://www.paypal.com/my/signin?returnUri=%2Fmyaccount%2Fsummary",
    "https://support.microsoft.com/en-us/account-billing/reset-a-forgotten-microsoft-account-password-eff4f067-5042-c1a3-fe72-b04d60556c37",
]


SUSPICIOUS_HARD_CASES = [
    "http://google-login-security.example.com/account/verify",
    "http://paypal.com@malicious-login.example/verify",
    "http://xn--paypa1-login.com/verify",
    "http://192.0.2.10/paypal/verify-account",
    "http://microsoft-security-check.xyz/signin",
    "http://secure-login-maybank2u.top/account",
]


def test_hard_legitimate_urls_are_not_flagged_by_length_alone():
    predictor = PhishGuardPredictor()
    results = [predictor.predict(url) for url in LEGITIMATE_HARD_CASES]

    assert all(result["is_phishing"] is False for result in results)
    assert all(result["risk_score"] < 45 for result in results)


def test_suspicious_url_patterns_remain_detected():
    predictor = PhishGuardPredictor()
    results = [predictor.predict(url) for url in SUSPICIOUS_HARD_CASES]

    assert all(result["is_phishing"] is True for result in results)
    assert all(result["risk_score"] >= 70 for result in results)
