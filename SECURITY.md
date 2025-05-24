# Security Policy for ResiLIVE

We take the security of ResiLIVE seriously. This document outlines the security measures in place and provides guidance on reporting vulnerabilities.

## Implemented Security Measures

*   **HTTPS Enforcement:** In production environments, all HTTP traffic is automatically redirected to HTTPS to ensure encrypted communication between clients and the server.
*   **API Key Authentication:**
    *   The main data endpoint (`/api`) and the game access logging endpoint (`/api/log-access`) are protected and require a secret API key (`API_SECRET_KEY`) for access.
    *   It is crucial to generate a strong, unique, and random string for this API key in your production environment and store it securely in your `.env` file. Do not use weak or default keys.
*   **Password Security:** User passwords are never stored in plaintext. They are securely hashed using `bcrypt` before being stored in the database.
*   **Session Management:**
    *   User sessions are managed using `cookie-session`.
    *   Session cookies are configured with `HttpOnly` to prevent access via client-side JavaScript.
    *   In production, cookies are set with the `Secure` attribute, ensuring they are only transmitted over HTTPS.
    *   The `SameSite=Lax` attribute is used to provide protection against Cross-Site Request Forgery (CSRF) attacks related to session cookies.
*   **Cross-Site Request Forgery (CSRF) Protection:** The application employs `lusca` middleware to generate and validate CSRF tokens for all state-changing requests, mitigating CSRF attacks.
*   **Rate Limiting:** To protect against brute-force attacks on authentication and other sensitive endpoints, `express-rate-limit` is implemented, limiting the number of requests a client can make in a given time window.
*   **Security Headers:** The application sets several HTTP headers to enhance security:
    *   `X-Content-Type-Options: nosniff`: Prevents browsers from MIME-sniffing the content type.
    *   `X-Frame-Options: DENY`: Protects against clickjacking attacks by preventing the site from being embedded in iframes.
    *   `Content-Security-Policy (CSP)`: A restrictive CSP (`default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; connect-src 'self' https://*.firebaseio.com wss://*.firebaseio.com;`) is in place to mitigate XSS and other injection attacks. Further refinement of CSP to remove 'unsafe-inline' is a long-term goal.
    *   `Strict-Transport-Security (HSTS)`: In production, HSTS (`max-age=31536000; includeSubDomains`) is enabled to ensure browsers only communicate with the server over HTTPS.
*   **Firebase Security:**
    *   The application uses Google Cloud Firestore for its database. Firestore automatically encrypts all data at rest.
    *   The Firebase Admin SDK is used for backend database operations, following Google's recommended security practices for server-side integration.
*   **Input Validation:**
    *   The application implements some input validation, particularly for user authentication and authorization processes (e.g., checking user existence).
    *   A comprehensive review and enhancement of input validation across all user-supplied data fields is planned for future development to further strengthen protection against injection attacks and ensure data integrity.

## Reporting Vulnerabilities

We are committed to addressing security vulnerabilities quickly and responsibly. If you discover a security vulnerability, please report it to us by opening a GitHub issue with the 'security' label.

Please include the following details in your report:
*   A description of the vulnerability, including the potential impact.
*   Steps to reproduce the vulnerability.
*   Any relevant logs, screenshots, or proof-of-concept code.

We appreciate your efforts to help us keep ResiLIVE secure. Please allow a reasonable amount of time for us to investigate and address any reported vulnerabilities before making them public.

---

*This document reflects the security posture as of the last update. We are continuously working to improve the security of our platform.*
