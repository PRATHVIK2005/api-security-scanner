"""OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows Check."""

from scanner.models import Endpoint, Finding, Severity

SENSITIVE_BUSINESS_KEYWORDS = {
    "login": "Authentication / Credential Entry",
    "signin": "Authentication / Credential Entry",
    "signup": "Account Creation",
    "register": "Account Creation",
    "password_reset": "Account Recovery",
    "reset_password": "Account Recovery",
    "forgot_password": "Account Recovery",
    "otp": "Multi-Factor Verification",
    "verify_otp": "Multi-Factor Verification",
    "2fa": "Multi-Factor Verification",
    "coupon": "Promotional / Discount Redemption",
    "discount": "Promotional / Discount Redemption",
    "voucher": "Promotional / Discount Redemption",
    "checkout": "Purchase / Financial Transaction",
    "payment": "Purchase / Financial Transaction",
    "purchase": "Purchase / Financial Transaction",
    "transfer": "Funds / Asset Transfer",
    "withdraw": "Funds / Asset Transfer",
    "refund": "Financial Transaction",
}


def check_business_flow(
    endpoint: Endpoint | str,
    method: str = "POST",
) -> list[Finding]:
    """
    Detect endpoints supporting sensitive business flows (e.g., login, checkout, coupon redemption)
    that may be vulnerable to automated abuse, credential stuffing, or business logic exploitation.
    """
    if isinstance(endpoint, Endpoint):
        endpoint_url = endpoint.url
        path = endpoint.path.lower()
        method = endpoint.method
        op_id = (endpoint.operation_id or "").lower()
        summary = (endpoint.summary or "").lower()
        description = (endpoint.description or "").lower()
        tags = " ".join([t.lower() for t in endpoint.tags])
    else:
        endpoint_url = str(endpoint)
        path = str(endpoint).lower()
        op_id = ""
        summary = ""
        description = ""
        tags = ""

    combined_text = f"{path} {op_id} {summary} {description} {tags}"
    matched_flow = None
    matched_category = None

    for keyword, category in SENSITIVE_BUSINESS_KEYWORDS.items():
        # Check normalized keyword match
        clean_kw = keyword.replace("_", "")
        clean_text = combined_text.replace("_", "").replace("-", "")
        if keyword in combined_text or clean_kw in clean_text:
            matched_flow = keyword
            matched_category = category
            break

    if matched_flow and matched_category:
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Potential Unrestricted Sensitive Business Flow",
                endpoint=endpoint_url,
                method=method,
                owasp="API6:2023 - Unrestricted Access to Sensitive Business Flows",
                description=(
                    f"The endpoint appears to handle a sensitive business flow ({matched_category} - '{matched_flow}'). "
                    "Without comprehensive rate-limiting, CAPTCHA, or anti-automation defenses, automated bots can exploit this flow for credential stuffing, resource exhaustion, or financial abuse."
                ),
                recommendation=(
                    "Implement robust multi-layered defenses for sensitive business flows: rate limiting per IP/user, CAPTCHA/bot protection, transaction limits, and anomaly detection."
                ),
            )
        ]

    return []
