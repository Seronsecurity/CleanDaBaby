# CleanDaBaby
A combination of functions to "clean" any text input. Includes: Normalization + Allowlist/Whitelist + Strip/Decode + DOMPurify + Parameterization of queries + Length limits. Stay safe!



# Composed of:
1. Allowlist (Whitelist) Input
Only permit characters/patterns you explicitly expect. Reject everything else.
js// Only allow alphanumeric + spaces
if (!/^[a-zA-Z0-9 ]+$/.test(input)) throw new Error("Invalid input");
Far safer than trying to blocklist known-bad patterns.

2. Strip or Encode Dangerous Characters
For HTML contexts, encode < > & " ' as their HTML entities to neutralize XSS.
jsconst sanitized = input
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;");
Use a well-tested library (e.g., DOMPurify for HTML, he for entity encoding) rather than rolling your own.

3. Use Parameterized Queries (Never Interpolate into SQL)
# BAD
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
# GOOD
cursor.execute("SELECT * FROM users WHERE name = %s", (user_input,))

This is the canonical defense against SQL injection — sanitizing the string itself is the wrong approach here.

4. Enforce Length Limits
jsif (input.length > 255) throw new Error("Input too long");
Prevents buffer overflows, DoS via resource exhaustion, and database truncation surprises.

5. Normalize Before Sanitizing
Unicode has multiple representations for the same character. Normalize first so your sanitizer isn't bypassed by homoglyphs or alternate encodings.
jsconst normalized = input.normalize("NFC").trim();

6. Context-Specific Escaping at Output
Sanitize once on input; escape at the point of use based on context:
# Output Context    Defense
HTML body           HTML entity encoding
HTML attribute      Attribute encoding
JavaScript          JS string escaping
SQL                 Parameterized queries
Shell commands      Avoid; use APIs instead
URLs                encodeURIComponent()

7. Content Security Policy (CSP)
A defense-in-depth HTTP header that limits what can execute in the browser even if XSS slips through.
Content-Security-Policy: default-src 'self'; script-src 'self'

# Common Pitfalls
# Sanitizing on the client only 
trivially bypassed; always sanitize server-side

# Blocklisting bad strings
attackers find encodings you didn't anticipate (%3Cscript%3E, double-encoding, null bytes)

# Trusting sanitized HTML from a rich-text editor
use a purpose-built library like DOMPurify, not manual stripping

# Sanitizing after storage
store raw (or at minimum validated) input, escape at render time; double-sanitizing causes data corruption

# Recommended Libraries by Stack
Stack              Library
JavaScript (HTML)  DOMPurify
Python             bleach, markupsafe
Java               OWASP Java HTML Sanitizer
PHP                HTMLPurifier
.NET               HtmlSanitizer (Ganss)

# Note
The OWASP Input Validation Cheat Sheet and XSS Prevention Cheat Sheet are authoritative references worth bookmarking.
