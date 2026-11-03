"""Untrusted/malformed internal wire responses must never become partial state."""
import json
import pytest
from firewalla_mcp.forward_policy import PROJECTION_FIELDS, read_projection


def row(values=None):
    return ['1', True, False, 'a'*40, [], values or []]


def read(rows, version=1):
    return read_projection(lambda args: json.dumps({'version': version, 'rows': rows}))


def field(name):
    return PROJECTION_FIELDS.index(name)+1


def test_sparse_projection_preserves_missing_empty_and_false_strings():
    result=read([row([field('target'), '', field('disabled'), '0', field('trust'), 'false'])])[0]
    assert result['target']=='' and result['disabled']=='0' and result['trust']=='false'
    assert 'scope' not in result and result['pid']=='1'


def test_empty_lua_tables_and_empty_inventory():
    assert read({})==[] and read([])==[]
    item=row();item[4]={};item[5]={}
    assert read([item])[0]['unknown_fields']==[]


@pytest.mark.parametrize('values', [
    [field('type')], [0,'x'], [len(PROJECTION_FIELDS)+1,'x'],
    [True,'x'], ['1','x'], [1.0,'x'], [field('pid'),'2'],
    [field('type'),'dns',field('type'),'net'],
    [field('type'),None], [field('type'),False], [field('type'),{}],
    [field('type'),'x']*len(PROJECTION_FIELDS),
])
def test_invalid_sparse_values_rejected(values):
    with pytest.raises(ValueError):read([row(values)])


@pytest.mark.parametrize('index,value', [
    (0,1),(0,'bad-id'),(1,'true'),(2,'false'),(3,1),(3,'a'*39),
    (4,['invalid\nfield']),(4,['x']*97),(5,{'1':'dns'}),
])
def test_invalid_metadata_rejected(index,value):
    item=row();item[index]=value
    with pytest.raises(ValueError):read([item])


@pytest.mark.parametrize('rows', [[row()[:-1]],[row()+['extra']],[{}],None,'secret'])
def test_invalid_row_shape_rejected(rows):
    with pytest.raises(ValueError):read(rows)


@pytest.mark.parametrize('version', [0,2,True,'1',None])
def test_unknown_wire_version_rejected(version):
    with pytest.raises(ValueError):read([],version)


def test_duplicate_ids_and_excess_inventory_rejected():
    with pytest.raises(ValueError):read([row(),row()])
    with pytest.raises(ValueError):read([row()]*513)


def test_value_bytes_and_aggregate_bound():
    assert read([row([field('target'),'x'*8192])])
    with pytest.raises(ValueError):read([row([field('target'),'x'*8193])])
    rows=[]
    for i in range(11):
        item=row([field('target'),'x'*(8192 if i<10 else 8080)])
        item[0]=str(i+1);rows.append(item)
    assert len(read(rows))==11
    rows[-1][5][-1]+='x'
    with pytest.raises(ValueError):read(rows)


def test_raw_response_bound_and_sanitized_parse_failure():
    for raw in (' '*131073, 'ERR PRIVATE_SYNTHETIC_SENTINEL', '{}',
                '{"version":1,"rows":[],"rows":[]}'):
        with pytest.raises(ValueError) as error:
            read_projection(lambda args:raw)
        assert 'PRIVATE_SYNTHETIC_SENTINEL' not in str(error.value)


def test_value_bounds_count_utf8_bytes():
    assert read([row([field('target'),'é'*4096])])
    with pytest.raises(ValueError):read([row([field('target'),'é'*4097])])


def test_schema_indices_preserve_all_allowed_fields():
    values=[]
    for i,name in enumerate(PROJECTION_FIELDS,1):
        if name!='pid':values.extend([i,'value:'+name])
    result=read([row(values)])[0]
    for name in PROJECTION_FIELDS:
        assert result[name]==('1' if name=='pid' else 'value:'+name)
