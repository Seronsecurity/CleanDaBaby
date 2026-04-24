/**
 * sanitize.js
 * Production-grade input sanitization utility for JavaScript.
 * Defense-in-depth: validate → normalize → sanitize → escape at output.
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULTS = {
  maxLength: 1024,
};

// ─── Primitive Helpers ────────────────────────────────────────────────────────

/**
 * Coerce input to a string and trim whitespace.
 * Rejects non-string/number types early.
 */
function coerceToString(input) {
  if (input === null || input === undefined) return "";
  if (typeof input === "object") throw new TypeError("Object inputs are not allowed.");
  return String(input).trim();
}

/**
 * Unicode normalization (NFC) prevents homoglyph attacks and
 * ensures consistent byte representation before pattern matching.
 */
function normalize(str) {
  return str.normalize("NFC");
}

/**
 * Enforce a hard length cap. Truncation is safer than rejection
 * in UI contexts; throw instead if your domain requires strictness.
 */
function enforceLength(str, maxLength = DEFAULTS.maxLength) {
  if (str.length > maxLength) {
    console.warn(`[sanitize] Input truncated from ${str.length} to ${maxLength} chars.`);
    return str.slice(0, maxLength);
  }
  return str;
}

/**
 * Strip null bytes and non-printable ASCII control characters
 * (except tab, newline, carriage return which are often intentional).
 */
function stripControlChars(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

// ─── Context-Specific Escaping ────────────────────────────────────────────────

/**
 * HTML entity encoding — safe for injecting into HTML text nodes and attributes.
 * Do NOT use this for innerHTML; use DOMPurify for rich HTML.
 */
function escapeHTML(str) {
  const map = {
    "&":  "&amp;",
    "<":  "&lt;",
    ">":  "&gt;",
    '"':  "&quot;",
    "'":  "&#x27;",
    "/":  "&#x2F;",
    "`":  "&#x60;",
    "=":  "&#x3D;",
  };
  return str.replace(/[&<>"'`=/]/g, (char) => map[char]);
}

/**
 * URL-encode a value for safe inclusion in a query string or path segment.
 */
function escapeURL(str) {
  return encodeURIComponent(str);
}

/**
 * JSON-safe escaping for embedding user input into JS string literals.
 * Returns the fully quoted JSON string.
 */
function escapeJS(str) {
  return JSON.stringify(str);
}

// ─── Pattern-Based Validators ─────────────────────────────────────────────────

const PATTERNS = {
  /** No HTML tags or angle brackets */
  plainText:    /^[^<>]*$/,
  /** Alphanumeric only */
  alphanumeric: /^[a-zA-Z0-9]+$/,
  /** Standard email — RFC 5322-ish, good enough for UI gating */
  email:        /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,
  /** URL with http/https scheme */
  url:          /^https?:\/\/[^\s/$.?#].[^\s]*$/i,
  /** Digits only */
  numeric:      /^\d+$/,
  /** UUID v4 */
  uuid:         /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
};

/**
 * Allowlist validation — returns true if input matches the named pattern.
 * @param {string} str
 * @param {"plainText"|"alphanumeric"|"email"|"url"|"numeric"|"uuid"} patternName
 */
function validate(str, patternName) {
  const pattern = PATTERNS[patternName];
  if (!pattern) throw new Error(`Unknown pattern: "${patternName}"`);
  return pattern.test(str);
}

// ─── Threat Detection ─────────────────────────────────────────────────────────
// These are belt-and-suspenders logging aids.
// Primary defenses are parameterized queries + escaping, not detection.

const SQL_INJECTION_PATTERNS = [
  /(\b)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|EXECUTE|CAST|CONVERT|DECLARE)\b/gi,
  /--|;|\/\*|\*\//g,
  /\b(OR|AND)\b\s+\d+=\d+/gi,
  /xp_|sp_/gi,
];

function detectSQLInjection(str) {
  return SQL_INJECTION_PATTERNS.some((re) => re.test(str));
}

const XSS_PATTERNS = [
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript\s*:/gi,
  /on\w+\s*=\s*["'][^"']*["']/gi,
  /<iframe|<object|<embed|<form/gi,
  /expression\s*\(/gi,
  /vbscript\s*:/gi,
];

function detectXSS(str) {
  return XSS_PATTERNS.some((re) => re.test(str));
}

// ─── Main Sanitizer ───────────────────────────────────────────────────────────

/**
 * Full sanitization pipeline.
 *
 * @param {*}      rawInput
 * @param {object} options
 * @param {number}  options.maxLength     - Hard character limit (default: 1024)
 * @param {boolean} options.stripHTML     - Strip all HTML tags (default: true)
 * @param {boolean} options.escapeOutput  - HTML-encode for DOM injection (default: false)
 * @param {string|null} options.validate  - Run a named pattern validation (optional)
 * @returns {{ value: string, warnings: string[] }}
 */
function sanitize(rawInput, options = {}) {
  const {
    maxLength    = DEFAULTS.maxLength,
    stripHTML    = true,
    escapeOutput = false,
    validate: validationPattern = null,
  } = options;

  const warnings = [];
  let str;

  // 1. Coerce
  try {
    str = coerceToString(rawInput);
  } catch (e) {
    return { value: "", warnings: [`Coercion failed: ${e.message}`] };
  }

  // 2. Normalize Unicode
  str = normalize(str);

  // 3. Strip control characters
  str = stripControlChars(str);

  // 4. Enforce length
  str = enforceLength(str, maxLength);

  // 5. Threat detection (warn only)
  if (detectXSS(str))          warnings.push("Potential XSS pattern detected.");
  if (detectSQLInjection(str)) warnings.push("Potential SQL injection pattern detected.");

  // 6. Strip HTML tags (naive — use DOMPurify for rich HTML)
  if (stripHTML) {
    str = str.replace(/<[^>]*>/g, "");
    str = str.replace(/&\w+;/g, "");
  }

  // 7. Allowlist validation
  if (validationPattern && !validate(str, validationPattern)) {
    warnings.push(`Input failed "${validationPattern}" validation.`);
  }

  // 8. Context escaping
  if (escapeOutput) {
    str = escapeHTML(str);
  }

  return { value: str, warnings };
}

// ─── Field-Type Shortcuts ─────────────────────────────────────────────────────

const sanitizers = {
  /** Plain text field: strip HTML, encode output, max 512 */
  text: (input) =>
    sanitize(input, { maxLength: 512, stripHTML: true, escapeOutput: true }),

  /** Email: lowercase, validate format, max 254 (RFC 5321) */
  email: (input) => {
    const { value, warnings } = sanitize(input, { maxLength: 254, stripHTML: true });
    const lower = value.toLowerCase();
    if (!validate(lower, "email")) warnings.push("Invalid email format.");
    return { value: lower, warnings };
  },

  /** URL: validate scheme, max 2048 */
  url: (input) => {
    const { value, warnings } = sanitize(input, { maxLength: 2048, stripHTML: true });
    if (!validate(value, "url")) warnings.push("Invalid or non-http(s) URL.");
    return { value, warnings };
  },

  /** Numeric: digits only */
  numeric: (input) => {
    const { value, warnings } = sanitize(input, { maxLength: 20, stripHTML: true });
    if (!validate(value, "numeric")) warnings.push("Non-numeric characters found.");
    return { value: value.replace(/\D/g, ""), warnings };
  },

  /** Textarea: strip HTML, encode output, max 4096 */
  textarea: (input) =>
    sanitize(input, { maxLength: 4096, stripHTML: true, escapeOutput: true }),

  /** Search query: strip HTML, encode output, max 256 */
  search: (input) =>
    sanitize(input, { maxLength: 256, stripHTML: true, escapeOutput: true }),
};

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  sanitize,
  sanitizers,
  escapeHTML,
  escapeURL,
  escapeJS,
  validate,
  detectXSS,
  detectSQLInjection,
  PATTERNS,
};

// ─── Usage Examples ───────────────────────────────────────────────────────────

if (require.main === module) {
  const examples = [
    { label: "Clean text",        fn: () => sanitizers.text("Hello, World!") },
    { label: "XSS attempt",       fn: () => sanitizers.text('<script>alert("xss")</script>') },
    { label: "SQL injection",      fn: () => sanitizers.text("' OR 1=1; DROP TABLE users--") },
    { label: "Valid email",        fn: () => sanitizers.email("  User@Example.COM  ") },
    { label: "Invalid email",      fn: () => sanitizers.email("not-an-email") },
    { label: "Valid URL",          fn: () => sanitizers.url("https://example.com/path?q=1") },
    { label: "Non-https URL",      fn: () => sanitizers.url("ftp://badscheme.com") },
    { label: "Numeric field",      fn: () => sanitizers.numeric("  00123abc  ") },
    { label: "Unicode (decomposed)", fn: () => sanitizers.text("caf\u0065\u0301") },
    { label: "Null byte",          fn: () => sanitizers.text("hello\x00world") },
  ];

  for (const { label, fn } of examples) {
    const result = fn();
    console.log(`\n[${label}]`);
    console.log("  value:   ", JSON.stringify(result.value));
    if (result.warnings.length) {
      console.log("  warnings:", result.warnings);
    }
  }
}
