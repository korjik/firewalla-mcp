import io
import stat
import zipfile

import pytest

from firewalla_mcp.vpn_archive import read_profile_archive
from firewalla_mcp.vpn_import import ImportBlocked, digest, validate_profile
from test_vpn_import import profile  # noqa: F401


def archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as output:
        for name, content in entries:
            output.writestr(name, content)
    return buffer.getvalue()


def test_three_opaque_profiles_preserved():
    entries = [(name + '.ovpn', b'synthetic private material') for name in ('a', 'b', 'c')]
    assert read_profile_archive(archive(entries)) == dict(entries)


@pytest.mark.parametrize('name', ['../a.ovpn', '/a.ovpn', 'a/b.ovpn', 'a\\b.ovpn', 'a\x00.ovpn', '.a.ovpn', 'extra.txt'])
def test_unsafe_member_names(name):
    with pytest.raises(ImportBlocked):
        read_profile_archive(archive([(name, b'x')]))


def test_case_collision():
    with pytest.raises(ImportBlocked, match='Duplicate'):
        read_profile_archive(archive([('A.ovpn', b'x'), ('a.ovpn', b'y')]))


def test_symlink():
    info = zipfile.ZipInfo('a.ovpn')
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ImportBlocked, match='type'):
        read_profile_archive(archive([(info, b'outside')]))


@pytest.mark.parametrize('entries', [[], [(f'{i}.ovpn', b'x') for i in range(4)], [('a.ovpn', b'x' * 131073)]])
def test_count_and_size_bounds(entries):
    with pytest.raises(ImportBlocked):
        read_profile_archive(archive(entries))


def test_compression_ratio_bound():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr('a.ovpn', b'x' * 100000)
    with pytest.raises(ImportBlocked, match='bounds'):
        read_profile_archive(buffer.getvalue())


def test_corrupt_archive_safe_error():
    with pytest.raises(ImportBlocked, match='Invalid or unreadable') as error:
        read_profile_archive(b'synthetic-sensitive-content')
    assert 'sensitive' not in str(error.value)


@pytest.mark.parametrize('extra', [b'comp-lzo\n', b'comp-lzo no\n', b'comp-lzo adaptive\n',
                                  b'key-direction 1\n<tls-auth>\nsynthetic-key\n</tls-auth>\n'])
def test_unreviewed_provider_features_rejected_without_mutation(profile, extra):
    content = profile + extra
    before = content[:]
    with pytest.raises(ImportBlocked) as error:
        validate_profile(content, digest(content), 'vpn.example.test')
    assert content == before
    assert 'synthetic-key' not in str(error.value)


def test_explicit_macos_metadata_option_preserves_only_profile_bytes():
    data=archive([('a.ovpn',b'opaque'),('__MACOSX/._a.ovpn',b'ignored')])
    with pytest.raises(ImportBlocked):read_profile_archive(data)
    assert read_profile_archive(data,allow_macos_metadata=True)=={'a.ovpn':b'opaque'}


@pytest.mark.parametrize('name',['__MACOSX/._missing.ovpn','__MACOSX/../a.ovpn','__MACOSX/._a.ovpn/extra'])
def test_metadata_must_match_exact_profile(name):
    with pytest.raises(ImportBlocked):read_profile_archive(archive([('a.ovpn',b'x'),(name,b'y')]),allow_macos_metadata=True)
