"""Exercise real nfprofile publication, migration, and legacy stat locking."""
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

binroot = Path(os.environ['BINDIR']).resolve()
profiler = binroot / 'nfsen/nfprofile'
generator = binroot / 'test/nfgen4'
if not profiler.exists() or not generator.exists():
    raise SystemExit(77)

with tempfile.TemporaryDirectory(prefix='nfprofile-compat-') as work:
    root = Path(work)
    subprocess.run([str(generator)], cwd=root, check=True, capture_output=True)
    fixture = root / 'dummy_flows.nf'
    data = root / 'profiles'
    data.mkdir()
    sources = root / 'input'
    sources.mkdir()

    def setup(name):
        channel = data / 'group' / name / 'channel'
        channel.mkdir(parents=True)
        (channel.parent / 'channel-filter.txt').write_text('any\n')
        return channel

    def command(name, slot):
        source = sources / time.strftime('nfcapd.%Y%m%d%H%M', time.localtime(slot))
        if not source.exists():
            shutil.copyfile(fixture, source)
        return [str(profiler), '-I', '-p', str(data), '-r', str(source),
                '-t', str(slot), '-W', '2', '-x', 'geodb.path=none', '-x', 'tordb.path=none']

    def run(name, slot, expected=0):
        # Type 8 publishes channel files but skips RRD updates.
        result = subprocess.run(command(name, slot), input=f'group#{name}#8#channel#*\n',
                                text=True, capture_output=True, timeout=30)
        assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)

    def stats(channel):
        return {key: int(value) for key, value in
                (line.split('=', 1) for line in (channel / '.nfstat').read_text().splitlines())}

    slot = 1767225600
    channel = setup('new')
    run('new', slot)
    first = stats(channel)
    assert (channel / '.nfcapd.book').exists()
    assert first['numfiles'] == 1 and first['first'] == slot and first['last'] == slot
    assert first['status'] == 0 and first['watermark'] == 95
    run('new', slot)
    assert stats(channel) == first, 'same slot double-counted'
    run('new', slot - 300)
    assert stats(channel) == first, 'older slot changed legacy totals'
    run('new', slot + 300)
    assert stats(channel)['numfiles'] == 2 and stats(channel)['last'] == slot + 300
    print('PASS: new channel, repeated/older/newer slots')

    channel = setup('migrate')
    archive = channel / '2025' / '12' / '31'
    archive.mkdir(parents=True)
    oldname = time.strftime('nfcapd.%Y%m%d%H%M', time.localtime(slot - 300))
    shutil.copyfile(fixture, archive / oldname)
    oldsize = (archive / oldname).stat().st_blocks * 512
    (channel / '.nfstat').write_text('first=1\nlast=2\nsize=999\nnumfiles=999\n'
                                    'maxsize=123456789\nlifetime=86400\nwatermark=80\nstatus=3\n')
    run('migrate', slot)
    migrated = stats(channel)
    assert migrated['numfiles'] == 2 and migrated['first'] == slot - 300
    assert migrated['maxsize'] == 123456789 and migrated['lifetime'] == 86400
    assert migrated['watermark'] == 80 and migrated['status'] == 0
    newname = time.strftime('nfcapd.%Y%m%d%H%M', time.localtime(slot))
    assert migrated['size'] == oldsize + (channel / newname).stat().st_blocks * 512
    print('PASS: existing archive scanned once, retention settings preserved')

    # A NfSen reader must see unchanged contents until it releases LOCK_SH.
    statfile = channel / '.nfstat'
    previous = statfile.read_bytes()
    with statfile.open('rb') as reader:
        fcntl.flock(reader, fcntl.LOCK_SH)
        process = subprocess.Popen(command('migrate', slot + 300), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            process.stdin.write('group#migrate#8#channel#*\n')
            process.stdin.close()
            process.stdin = None
            target = channel / time.strftime('nfcapd.%Y%m%d%H%M', time.localtime(slot + 300))
            deadline = time.monotonic() + 10
            while not target.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert target.exists(), 'profiler did not reach publication'
            time.sleep(0.2)
            assert process.poll() is None, 'writer did not wait for shared lock'
            assert statfile.read_bytes() == previous, 'file truncated before acquiring lock'
            fcntl.flock(reader, fcntl.LOCK_UN)
            process.communicate(timeout=10)
            assert process.returncode == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
    assert stats(channel)['numfiles'] == 3
    print('PASS: NfSen shared lock protects statistics until publication')

    statfile.unlink()
    statfile.mkdir()
    run('migrate', slot + 600, expected=1)
    statfile.rmdir()
    run('migrate', slot + 600)
    assert stats(channel)['numfiles'] == 4, 'failed stat export caused double accounting'
    print('PASS: export errors propagate and retry does not double-count')

    channel = setup('recover')
    run('recover', slot)
    blocked = channel / time.strftime('nfcapd.%Y%m%d%H%M', time.localtime(slot + 300))
    blocked.mkdir()
    run('recover', slot + 300, expected=1)
    blocked.rmdir()
    run('recover', slot + 300)
    assert stats(channel)['numfiles'] == 2 and stats(channel)['status'] == 0
    print('PASS: interrupted publication leaves a dirty book that is recovered')

    channel = setup('expirefirst')
    shutil.copyfile(fixture, channel / oldname)
    (channel / '.nfstat').write_text('maxsize=123456789\nlifetime=86400\nwatermark=80\n')
    subprocess.run([str(binroot / 'nfexpire/nfexpire'), '-Y', '-p', '-r', str(channel.parent)],
                   check=True, capture_output=True, timeout=30)
    expired = stats(channel)
    assert expired['numfiles'] == 1 and expired['maxsize'] == 123456789
    assert expired['lifetime'] == 86400 and expired['watermark'] == 80
    # Once migrated, subsequent exports must use the book, not edited legacy limits.
    (channel / '.nfstat').write_text('maxsize=1\nlifetime=1\nwatermark=1\n')
    run('expirefirst', slot)
    assert stats(channel)['numfiles'] == 2 and stats(channel)['maxsize'] == 123456789
    print('PASS: nfexpire-first upgrade preserves limits; book remains authoritative')
