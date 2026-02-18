import re

# Read the file
with open(r'toys\php_deserialization.yaml', 'r') as f:
    content = f.read()

# Find the line with "Unable to filehdmi" or similar garbage
# and remove everything from there until the end
pattern = r'(    - "Unable to unserialize"\n).*'
content = re.sub(pattern, r'\1\n\nremediation: |\n  Never use unserialize() on untrusted user input. Use json_decode() or other safe\n  alternatives instead. If you must use unserialize(), implement strict validation\n  and use allowed_classes parameter. Keep PHP updated to receive security patches.\n\nreferences:\n  - "https://www.owasp.org/index.php/Deserialization_of_untrusted_data"\n  - "https://www.php.net/manual/en/function.unserialize.php"\n  - "https://phpggc.github.io/"', content, flags=re.DOTALL)

# Write the file back
with open(r'toys\php_deserialization.yaml', 'w') as f:
    f.write(content)

print("PHP file cleaned")
