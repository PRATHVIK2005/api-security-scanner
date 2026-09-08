"""Centralized OWASP API Security Top 10 (2023) knowledge base and remediation guidance."""

FINDING_KNOWLEDGE = {
    # -------------------------------------------------------------
    # API1:2023 - Broken Object Level Authorization (BOLA)
    # -------------------------------------------------------------
    "Potential Broken Object Level Authorization Risk": {
        "owasp": "API1:2023 - Broken Object Level Authorization",
        "description": (
            "This endpoint references a specific object identifier in its route or parameters. "
            "Ensure object-level access control policies verify that the requesting user owns or has explicit permissions for this resource."
        ),
        "recommendation": (
            "Implement authorization checks at the data/service layer to validate that the active session user has permission to access the requested resource ID."
        ),
    },
    "Potential Broken Object Level Authorization": {
        "owasp": "API1:2023 - Broken Object Level Authorization",
        "description": (
            "This endpoint references a specific object identifier in its route or parameters. "
            "Ensure object-level access control policies verify that the requesting user owns or has explicit permissions for this resource."
        ),
        "recommendation": (
            "Implement authorization checks at the data/service layer to validate that the active session user has permission to access the requested resource ID."
        ),
    },

    # -------------------------------------------------------------
    # API2:2023 - Broken Authentication
    # -------------------------------------------------------------
    "Potential Missing Authentication": {
        "owasp": "API2:2023 - Broken Authentication",
        "description": (
            "A potentially sensitive API endpoint appears to be accessible without authentication or does not declare authentication requirements."
        ),
        "recommendation": (
            "Require strong authentication (e.g. OAuth2, JWT Bearer) before allowing access to sensitive resources."
        ),
    },
    "JWT Token Exposed in Response": {
        "owasp": "API2:2023 - Broken Authentication",
        "description": (
            "A JSON Web Token (JWT) appears to be exposed directly in the API response body."
        ),
        "recommendation": (
            "Avoid echoing authentication tokens unnecessarily. Use secure HTTP-only cookies or ephemeral bearer tokens and store them securely."
        ),
    },
    "Potential API Key Exposed in Response": {
        "owasp": "API2:2023 - Broken Authentication",
        "description": (
            "A potential API key, secret token, or private credential appears to be exposed in the API response."
        ),
        "recommendation": (
            "Remove secrets and credentials from responses. Store keys in environment variables or a dedicated secrets manager (e.g. AWS Secrets Manager, Vault)."
        ),
    },
    "Potential Password Exposure": {
        "owasp": "API2:2023 - Broken Authentication",
        "description": (
            "The API response appears to contain a plaintext password, password hash, or credential attribute."
        ),
        "recommendation": (
            "Never return password fields or password hashes in API responses. Filter user entities before serialization."
        ),
    },
    "Potential Private Key Exposure": {
        "owasp": "API2:2023 - Broken Authentication",
        "description": (
            "The API response appears to contain an unencrypted private cryptographic key."
        ),
        "recommendation": (
            "Immediately rotate the exposed key and ensure private keys are never transmitted via API responses."
        ),
    },

    # -------------------------------------------------------------
    # API3:2023 - Broken Object Property Level Authorization (BOPLA)
    # -------------------------------------------------------------
    "Potential Sensitive Object Property Exposure": {
        "owasp": "API3:2023 - Broken Object Property Level Authorization",
        "description": (
            "The API response or response schema contains sensitive internal object properties (e.g. internal flags, permissions, private keys) that should not be visible to general clients."
        ),
        "recommendation": (
            "Implement Data Transfer Objects (DTOs) or field-level filtering to ensure clients only receive properties they are explicitly authorized to read."
        ),
    },
    "Potential Writable Privileged Property": {
        "owasp": "API3:2023 - Broken Object Property Level Authorization",
        "description": (
            "The request body schema allows client-controlled properties (e.g. role, is_admin, permissions) that could enable mass assignment privilege escalation."
        ),
        "recommendation": (
            "Enforce strict input allow-lists for request models and prevent clients from directly binding privileged administrative fields."
        ),
    },

    # -------------------------------------------------------------
    # API4:2023 - Unrestricted Resource Consumption
    # -------------------------------------------------------------
    "Potential Missing Rate Limiting": {
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "description": (
            "The API response does not include standard rate limit headers (RateLimit-Limit or X-RateLimit-Limit)."
        ),
        "recommendation": (
            "Implement rate limiting per IP or authenticated user to prevent denial of service and resource exhaustion."
        ),
    },
    "Rate Limiting Not Verified": {
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "description": (
            "Active burst testing could not confirm that the API enforces rate limiting (HTTP 429 Too Many Requests)."
        ),
        "recommendation": (
            "Configure and verify request rate limits and throttling policies on all public and resource-intensive endpoints."
        ),
    },

    # -------------------------------------------------------------
    # API5:2023 - Broken Function Level Authorization (BFLA)
    # -------------------------------------------------------------
    "Exposed Administrative Endpoint": {
        "owasp": "API5:2023 - Broken Function Level Authorization",
        "description": (
            "An administrative endpoint (/admin) appears to be publicly accessible without expected authorization controls."
        ),
        "recommendation": (
            "Restrict administrative functions using role-based access control (RBAC), multi-factor authentication, and IP whitelisting."
        ),
    },
    "Exposed Management Endpoint": {
        "owasp": "API5:2023 - Broken Function Level Authorization",
        "description": (
            "A management or actuator endpoint (/manage, /actuator) appears to be publicly accessible."
        ),
        "recommendation": (
            "Restrict management endpoints to authorized system administrators and internal networks."
        ),
    },
    "Exposed Internal Endpoint": {
        "owasp": "API5:2023 - Broken Function Level Authorization",
        "description": (
            "An internal service endpoint (/internal) appears to be exposed on a public route."
        ),
        "recommendation": (
            "Isolate internal microservices within private network boundaries and deny public routing."
        ),
    },
    "Exposed Debug Endpoint": {
        "owasp": "API5:2023 - Broken Function Level Authorization",
        "description": (
            "A debug endpoint (/debug) is accessible, potentially exposing internal application state."
        ),
        "recommendation": (
            "Disable all debug and diagnostic endpoints in production deployments."
        ),
    },
    "Exposed Metrics Endpoint": {
        "owasp": "API5:2023 - Broken Function Level Authorization",
        "description": (
            "A telemetry or metrics endpoint (/metrics) is publicly reachable without authentication."
        ),
        "recommendation": (
            "Restrict monitoring endpoints to authorized scraping services within internal subnets."
        ),
    },
    "Potential Broken Function Level Authorization": {
        "owasp": "API5:2023 - Broken Function Level Authorization",
        "description": (
            "A privileged function appears to lack proper role-based access controls."
        ),
        "recommendation": (
            "Validate user roles and permissions on every privileged API operation before executing business logic."
        ),
    },

    # -------------------------------------------------------------
    # API6:2023 - Unrestricted Access to Sensitive Business Flows
    # -------------------------------------------------------------
    "Potential Unrestricted Sensitive Business Flow": {
        "owasp": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
        "description": (
            "The endpoint handles a critical business flow (e.g. login, checkout, password reset, OTP verification) that may be vulnerable to automated bot abuse."
        ),
        "recommendation": (
            "Implement multi-layered anti-automation defenses: rate limiting per user/IP, CAPTCHA on excessive attempts, and transaction velocity checks."
        ),
    },

    # -------------------------------------------------------------
    # API7:2023 - Server Side Request Forgery (SSRF)
    # -------------------------------------------------------------
    "Potential SSRF Input Risk": {
        "owasp": "API7:2023 - Server Side Request Forgery",
        "description": (
            "The endpoint accepts remote URL or destination parameters that may be fetched server-side, potentially exposing internal services."
        ),
        "recommendation": (
            "Strictly validate user-supplied URLs against an allow-list of schemes and domains. Block requests to internal RFC1918 IPs and cloud metadata (169.254.169.254)."
        ),
    },

    # -------------------------------------------------------------
    # API8:2023 - Security Misconfiguration
    # -------------------------------------------------------------
    "Missing X-Content-Type-Options Header": {
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The API response does not include the X-Content-Type-Options security header."
        ),
        "recommendation": (
            "Set X-Content-Type-Options to 'nosniff' to prevent MIME-type sniffing."
        ),
    },
    "Missing X-Frame-Options Header": {
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The API response does not include the X-Frame-Options security header."
        ),
        "recommendation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."
        ),
    },
    "Missing Security Headers": {
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The API response is missing standard security headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security)."
        ),
        "recommendation": (
            "Configure a reverse proxy or middleware to attach standard security headers to all HTTP responses."
        ),
    },
    "Overly Permissive CORS Policy": {
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The API allows requests from untrusted origins with an overly permissive CORS policy (Access-Control-Allow-Origin: *)."
        ),
        "recommendation": (
            "Restrict allowed origins, methods, and headers to trusted domain names."
        ),
    },
    "Dangerous HTTP Method Supported": {
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The endpoint supports potentially dangerous or unnecessary HTTP methods (such as TRACE or TRACK)."
        ),
        "recommendation": (
            "Disable unsupported or debugging HTTP methods on web servers and API gateways."
        ),
    },
    "Server Technology Information Exposed": {
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The API response reveals server or framework software versions in headers (Server, X-Powered-By)."
        ),
        "recommendation": (
            "Disable or sanitize banner headers like Server and X-Powered-By to prevent targeted version-specific reconnaissance."
        ),
    },
    "Potential Debug Information Exposure": {
        "owasp": "API8:2023 - Security Misconfiguration",
        "description": (
            "The API response contains stack traces, framework error messages, or internal runtime details."
        ),
        "recommendation": (
            "Use custom generic error handlers and ensure detailed stack traces are logged internally rather than returned to clients."
        ),
    },

    # -------------------------------------------------------------
    # API9:2023 - Improper Inventory Management
    # -------------------------------------------------------------
    "Potential Deprecated API Endpoint": {
        "owasp": "API9:2023 - Improper Inventory Management",
        "description": (
            "The endpoint name suggests that it may be a legacy, unmaintained, or deprecated API."
        ),
        "recommendation": (
            "Review whether this endpoint is still required and remove or restrict access to deprecated APIs."
        ),
    },
    "Potential Outdated API Version": {
        "owasp": "API9:2023 - Improper Inventory Management",
        "description": (
            "The endpoint appears to use an early or pre-release API version prefix (e.g. /v0/, /v1beta)."
        ),
        "recommendation": (
            "Maintain an updated inventory of active API versions and retire unsupported legacy versions."
        ),
    },
    "Deprecated OpenAPI Operation Declared": {
        "owasp": "API9:2023 - Improper Inventory Management",
        "description": (
            "The OpenAPI specification explicitly flags this operation as deprecated."
        ),
        "recommendation": (
            "Plan a migration path for API consumers and decommission the deprecated operation according to policy."
        ),
    },

    # -------------------------------------------------------------
    # API10:2023 - Unsafe Consumption of APIs
    # -------------------------------------------------------------
    "Potential Unsafe External API Consumption": {
        "owasp": "API10:2023 - Unsafe Consumption of APIs",
        "description": (
            "The endpoint appears to consume or proxy data from third-party services or webhooks without obvious validation controls."
        ),
        "recommendation": (
            "Validate and sanitize all data received from external third-party APIs. Require cryptographic signatures for webhooks and enforce TLS."
        ),
    },
}


def get_finding_knowledge(title: str) -> dict:
    """Return security information and remediation advice for a finding."""
    return FINDING_KNOWLEDGE.get(
        title,
        {
            "owasp": "Security Assessment Item",
            "description": "A potential security risk or configuration issue was detected during the API audit.",
            "recommendation": "Review the security finding and apply defense-in-depth best practices.",
        },
    )