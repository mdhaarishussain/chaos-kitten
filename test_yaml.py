import yaml
with open('toys/python_deserialization.yaml') as f:
    data = yaml.safe_load(f)
print('Python payloads:', len(data['payloads']))
print('Python indicators:', len(data['success_indicators']['response_contains']))
print('File is valid YAML')
