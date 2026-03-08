# Advanced Deserialization Attack Profiles

## Overview
Insecure deserialization occurs when untrusted data is used to abuse the logic of an application, inflict a denial of service (DoS) attack, or even execute arbitrary code upon it being deserialized.

Chaos Kitten provides advanced detection and exploitation profiles for insecure deserialization across multiple languages, including **Java**, **Python**, **PHP**, and **Ruby**.

## Language Detection
Chaos Kitten's `AttackPlanner` analyzes Open API specifications to automatically detect potential deserialization endpoints:
- **Paths**: Specific extensions (`.php`, `.jsp`, `.do`, `.py`, `.rb`).
- **Content-Type Headers**: Headers such as `application/x-java-serialized-object`, `application/python-pickle`, etc.
- **Parameters**: Detection of known indicators within query or body parameters (e.g. `java_obj`, `pickle`, `php_serial`).

When a specific language is identified, Chaos Kitten only injects the appropriate gadget chains for that language to minimize noise.

## Payloads and Gadget Chains

### Java
Java deserialization vulnerabilities are typically exploited by supplying serialized objects mapped to gadget chains that lead to Remote Code Execution (RCE).
- **Indicators**: `java.io.InvalidClassException`, `java.lang.Runtime`, `org.apache.commons.collections`
- **Common Gadgets**:
  - Magic Bytes: `rO0AB...`
  - CommonsCollections1 via ysoserial
  - Spring1, Hibernate, etc.

### Python
Python is vulnerable to unsafe deserialization through `pickle` and `PyYAML`'s `unsafe_load()`.
- **Indicators**: `pickle.UnpicklingError`, `yaml.constructor.ConstructorError`
- **Common Gadgets**:
  - `pickle` RCE: `cos\nsystem\n(S'id'\ntR.`
  - Base64 encoded payload: `gANjcG9zaXgKc3lzdGVtCnEAWAIAAABpZHEBhXECUnEDLg==`
  - PyYAML RCE: `!!python/object/apply:os.system ['id']`

### PHP
PHP's `unserialize()` can lead to Object Injection vulnerabilities if magic methods like `__wakeup()` or `__destruct()` are defined on classes available in the scope.
- **Indicators**: `PHP Fatal error: Uncaught`, `Object of class`
- **Common Gadgets**:
  - Object string representations: `O:8:"Exploit":1:{s:7:"command";s:2:"id";}`
  - Array wrapper bypasses
  - Known chains from `phpggc` (e.g. Monolog, Laravel routers)

### Ruby
Ruby can be vulnerable through `Marshal.load` and `YAML.load`.
- **Indicators**: `TypeError:`, `undefined class/module`
- **Common Gadgets**:
  - Marshal header: `\x04\x08` or base64 equivalent (`BAhbAA==`)
  - YAML load unsafe objects: `--- !ruby/object:Gem::Installer\n  i: x\n`
  - Deep generic gadgets: `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy`

## Adding Custom Gadgets
To add more payloads, update the corresponding `toys/deserialization_<lang>.yaml` file. Each file has a `payloads` array where raw string payloads can be added. Ensure payloads are appropriately escaped if using multi-line strings.
