with open(r'toys\python_deserialization.yaml', 'r') as f:
    lines = f.readlines()[:77]
with open(r'toys\python_deserialization.yaml', 'w') as f:
    f.writelines(lines)
print("File truncated successfully")
