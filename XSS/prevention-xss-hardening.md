# Cross-Site Scripting (XSS) – Prevention & Hardening

## 1. Remediation Strategy

During testing of the OWASP Juice Shop deployment, three independent cross-site scripting (XSS) vulnerabilities were identified:

- DOM-based XSS in the product search functionality
    
- Reflected XSS in the order tracking endpoint
    
- Stored XSS in the administration feedback interface
    

Each vulnerability originated from unsafe rendering of user-controlled input into the DOM.

The remediation strategy focused on the following secure coding principles:

```
1. Eliminate unsafe DOM rendering sinks
2. Avoid Angular sanitizer bypass mechanisms
3. Use Angular template interpolation for automatic escaping
4. Introduce explicit sanitization where HTML rendering is required
```

Detection logging was intentionally not implemented for this module. The vulnerabilities were mitigated directly through secure code remediation and removal of unsafe rendering patterns.

---

# 2. DOM-Based XSS Mitigation

## Root Cause

The product search page accepted user input through the query parameter:

```
/search?q=<payload>
```

The input value was rendered using Angular's sanitizer bypass mechanism:

```
DomSanitizer.bypassSecurityTrustHtml()
```

This disables Angular’s built-in XSS protection and allows arbitrary HTML to execute.

Example payload used during exploitation:

```
<iframe src="javascript:alert(`xss`)">
```

---

## Patch Location

```
frontend/src/app/search-result/search-result.component.ts
frontend/src/app/search-result/search-result.component.html
```

---

## Code Changes

### File

```
frontend/src/app/search-result/search-result.component.ts
```

### Before

```ts
this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
```

### After

```ts
this.searchValue = queryParam
```

The sanitizer bypass was removed, ensuring that the value is treated as plain text.

---

### File

```
frontend/src/app/search-result/search-result.component.html
```

### Before

```html
<span id="searchValue" [innerHTML]="searchValue"></span>
```

### After

```html
<span id="searchValue">{{ searchValue }}</span>
```

---

## Security Impact

Angular template interpolation automatically escapes HTML characters.

```
User Input → Angular Escaping → Safe DOM Rendering
```

Injected markup is therefore rendered as plain text rather than executable HTML.

---

# 3. Reflected XSS Mitigation

## Root Cause

The order tracking page accepted user-controlled identifiers through the URL:

```
/track-order?id=<payload>
```

The identifier was rendered using Angular’s sanitizer bypass mechanism, allowing injected HTML to execute within the page.

Example payload:

```
<iframe src="javascript:alert(`xss`)">
```

---

## Patch Location

```
frontend/src/app/track-result/track-result.component.ts
```

---

## Code Changes

### File

```
frontend/src/app/track-result/track-result.component.ts
```

### Before

```ts
this.results.orderNo = this.sanitizer.bypassSecurityTrustHtml(`<code>${results.data[0].orderId}</code>`)
```

### After

```ts
this.results.orderNo = '<code>${results.data[0].orderId}</code>'
```

---

## Security Impact

Removing the sanitizer bypass prevents user-controlled values from being inserted into the DOM as trusted HTML.

As a result, manipulated query parameters can no longer execute injected scripts.

---

# 4. Stored XSS Mitigation

## Root Cause

Customer feedback comments are user-generated content stored in the database and displayed in the administration interface.

The application previously rendered these comments using Angular’s `[innerHTML]` directive:

```
[innerHTML]
```

Rendering user-controlled data directly into the DOM allowed stored payloads to execute when administrators viewed feedback entries.

Example stored payload used during testing:

```
<<iframe src="javascript:evil"/>iframe src="javascript:alert(`xss`)">
```

---

## Patch Locations

```
frontend/src/app/administration/administration.component.html
frontend/src/app/administration/administration.component.ts
```

---

## Template Patch

### File

```
frontend/src/app/administration/administration.component.html
```

### Before

```html
<p [innerHTML]="feedback.comment"
   matTooltip="Click for more information"
   matTooltipPosition="above"></p>
```

### After

```html
<p [innerHTML]="sanitizeFeedback(feedback.comment)"
   matTooltip="Click for more information"
   matTooltipPosition="above"></p>
```

---

## Sanitization Logic

### File

```
frontend/src/app/administration/administration.component.ts
```

### Added Import

```ts
import { SecurityContext } from '@angular/core'
```

### Added Function

```ts
sanitizeFeedback(comment: string) {
  return this.sanitizer.sanitize(SecurityContext.HTML, comment)
}
```

---

## Security Impact

The sanitization step filters HTML content before it is inserted into the DOM.

Potentially dangerous elements such as:

```
<script>
<iframe>
javascript:
event handler attributes
```

are removed before rendering, preventing stored script execution in the administration interface.

---

# 5. Security Outcome

After the remediation steps were applied:

|Vulnerability|Status|
|---|---|
|DOM XSS|Mitigated|
|Reflected XSS|Mitigated|
|Stored XSS|Mitigated|

User-controlled content is no longer rendered directly as executable HTML within the application interface.

---

# 6. Secure Design Improvements

The remediation introduced several secure development improvements:

```
Removal of Angular sanitizer bypass functions

Elimination of unsafe DOM rendering sinks

Adoption of Angular template interpolation for user data

Introduction of explicit HTML sanitization for stored content
```

These changes significantly reduce the likelihood of future cross-site scripting vulnerabilities.

---

# 7. Educational Context and Real-World Relevance

The vulnerabilities addressed in this module originate from intentionally insecure patterns included in the OWASP Juice Shop application. These constructs are designed to simulate realistic security flaws for educational purposes.

For example, the application deliberately uses Angular’s `DomSanitizer.bypassSecurityTrustHtml()` in certain components to demonstrate how bypassing framework protections can lead to exploitable XSS conditions.

Although these insecure patterns are intentionally introduced in the training environment, the remediation performed in this project reflects **real-world secure coding practices** commonly applied when addressing cross-site scripting vulnerabilities in production systems.

The mitigation techniques implemented here demonstrate several widely accepted defensive strategies:

- Removing unsafe DOM rendering sinks
    
- Avoiding sanitizer bypass mechanisms that disable framework protections
    
- Rendering user input through framework-controlled escaping mechanisms
    
- Applying explicit sanitization when dynamic HTML rendering is unavoidable
    

While the vulnerable constructs in this environment are intentionally placed for learning purposes, the defensive changes implemented in this module represent **practical security hardening techniques used in real applications**.

This module therefore demonstrates the complete vulnerability lifecycle:

```
Discovery → Exploitation → Root Cause Analysis → Remediation → Validation
```

and reinforces secure development principles that extend beyond the training environment.

---
