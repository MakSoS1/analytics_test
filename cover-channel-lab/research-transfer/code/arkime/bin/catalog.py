from pipeline import OpenSearch,write_table,compact

def export_catalog(out):
 import pyarrow as pa
 schema=pa.schema([('field_id',pa.string()),('definition_json',pa.string())])
 return write_table(out,schema,(dict(field_id=h['_id'],definition_json=compact(h['_source'])) for h in OpenSearch().hits('office_arkime_fields')))
