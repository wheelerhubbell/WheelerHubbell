import json,sys
from pathlib import Path
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1]
for path in sorted((ROOT/'schemas').glob('*.json')):
    schema=json.loads(path.read_text());Draft202012Validator.check_schema(schema)
    print('SCHEMA_VALID',path.name)
for schema_path,instance_path in zip(sys.argv[1::2],sys.argv[2::2]):
    schema=json.loads(Path(schema_path).read_text());data=json.loads(Path(instance_path).read_text())
    Draft202012Validator(schema).validate(data);print('INSTANCE_VALID',Path(instance_path).name)
