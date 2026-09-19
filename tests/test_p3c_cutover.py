"""P3C rehearsal: no production host, credentials, services or DB connections."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
from dataclasses import replace
import subprocess
import sys
import shutil

import pytest

from pdi.production_ops import contracts as c
from pdi.production_ops import cutover as ops
from pdi.production_ops.database import Database
from pdi.production_ops.writer import DAILY, execute
from pdi.scoped_operator_config import load_scoped_operator_configuration
from pdi.principal import PrincipalId


ROOT = Path(__file__).resolve().parents[1]


def identity():
    uid = lambda i: str(UUID(int=i))
    return {'principal': {'id': uid(1), 'enabled': False, 'represents': 'existing-personal-world'},
            'provider_instances': dict(zip(c.PROVIDERS, map(uid, range(2, 6)))),
            'provider_accounts': {'nextcloud': uid(6), 'immich': uid(7)},
            'observation_scopes': {k: {'id': uid(i), 'enabled': False} for i, k in enumerate(c.SOURCE_MAPPING.values(), 8)},
            'policy': {'gmail_scoped_ingestion': 'disabled', 'integration_test_rows_to_delete': 0,
                       'legacy_rows_preserved': True, 'person_equals_principal': False}}


def transition():
    return {'initial_enablement': 'synthetic-disabled', 'legacy_rows_mutated': 'historical-value',
            'legacy_sync_state_copy': 'historical-value', 'source_mapping': dict(c.SOURCE_MAPPING)}


def plan():
    return c.Plan.parse(identity(), transition())


def environment():
    return {'DATABASE__URL': 'postgresql+psycopg://synthetic:synthetic-db-secret@localhost/synthetic_test',
            'NEXTCLOUD__URL': 'http://nextcloud.invalid', 'NEXTCLOUD__USER': 'synthetic',
            'NEXTCLOUD__PASSWORD': 'synthetic-nc-secret', 'IMMICH__URL': 'http://immich.invalid',
            'IMMICH__API_KEY': 'synthetic-immich-secret'}


def rollback():
    return {'FINAL_QUIESCED_SNAPSHOT_ID': 'a'*64, 'SOURCE_SHA': 'b'*40,
            'SOURCE_ALEMBIC': '5e7a9c2d1f30', 'POSTGRES_MAJOR': '16', 'WRITERS_QUIESCED': 'YES',
            'RESTORE_TESTED': 'YES', 'RESTORED_COUNTS_MATCH': 'YES',
            **{k: 'synthetic' for k in ('SOURCE_HOST', 'BACKUP_HOST', 'BACKUP_FS_UUID', 'BACKUP_FS_LABEL',
                'RESTIC_REPOSITORY_RELATIVE_PATH', 'PREVIOUS_QUALIFIED_SNAPSHOT_ID', 'FINAL_SNAPSHOT_TAGS')}}


def test_frozen_ids_and_transition_scalar_preserved():
    p = plan()
    assert p.principal == identity()['principal']['id']
    assert p.scopes['gmail'] == identity()['observation_scopes']['gmail_preservation']['id']
    assert p.scopes['integration-test'] == identity()['observation_scopes']['integration_test_quarantine']['id']
    assert p == plan()


@pytest.mark.parametrize('mutate', [
    lambda x: x['principal'].update(id='bad'),
    lambda x: x['principal'].update(enabled=True),
    lambda x: x['provider_instances'].pop('gmail'),
    lambda x: x['provider_accounts'].update(gmail=str(UUID(int=99))),
    lambda x: x['observation_scopes']['gmail_preservation'].update(enabled=True),
    lambda x: x['observation_scopes']['integration_test_quarantine'].update(enabled=True),
    lambda x: x['policy'].update(person_equals_principal=True),
    lambda x: x['policy'].update(integration_test_rows_to_delete=1),
    lambda x: x['provider_instances'].update(gmail=str(UUID(int=2))),
])
def test_bad_identity_refused(mutate):
    raw = identity()
    mutate(raw)
    with pytest.raises(c.Refused):
        c.Plan.parse(raw, transition())


def test_transition_no_backfill_or_guessed_historical_values():
    raw = transition()
    raw['legacy_rows_mutated'] = False
    raw['legacy_sync_state_copy'] = {'unknown-historical-shape': True}
    c.Plan.parse(identity(), raw)
    raw['initial_enablement'] = {}
    with pytest.raises(c.Refused):
        c.Plan.parse(identity(), raw)
    raw = transition()
    del raw['source_mapping']['integration-test']
    with pytest.raises(c.Refused):
        c.Plan.parse(identity(), raw)


@pytest.mark.parametrize('field', list(rollback()))
def test_missing_or_wrong_rollback_metadata_refused(field):
    raw = rollback()
    del raw[field]
    with pytest.raises(c.Refused):
        c.validate_rollback(raw, 'a'*64, 'b'*40)


def test_rollback_exact_not_prefix():
    c.validate_rollback(rollback(), 'a'*64, 'b'*40)
    with pytest.raises(c.Refused):
        c.validate_rollback(rollback(), 'c'*64, 'b'*40)


def test_registry_real_parser_and_minimal_env(tmp_path):
    p, env = plan(), environment()
    registry = c.registry_text(p, env)
    path = tmp_path / 'registry.toml'
    path.write_text(registry)
    cfg = load_scoped_operator_configuration(path, environment=env)
    assert cfg.router.resolve(p.principal).database_url == env['DATABASE__URL']
    assert len(cfg.bindings) == 2
    for provider in ('nextcloud', 'immich'):
        b, secret = cfg.resolve(PrincipalId(p.principal), UUID(p.scopes[provider]), provider)
        assert secret == env[b.secret_env]
    assert 'gmail' not in registry and 'integration-test' not in registry
    for k in ('DATABASE__URL', 'NEXTCLOUD__PASSWORD', 'IMMICH__API_KEY'):
        assert env[k] not in registry
    for name in c.PIPELINES:
        values = c.parse_env(c.unit_environment(p, env, name))
        assert values['DATABASE__URL'] == env['DATABASE__URL']
        assert ('IMMICH__API_KEY' not in values) == name.startswith('nextcloud-')
        assert ('NEXTCLOUD__PASSWORD' in values) == name.startswith('nextcloud-')
        # Loading a shared non-secret registry needs only this unit's secret.
        own = load_scoped_operator_configuration(path, environment=values)
        provider = 'nextcloud' if name.startswith('nextcloud-') else 'immich'
        own.resolve(PrincipalId(p.principal), UUID(p.scopes[provider]), provider)


@pytest.mark.parametrize('url', ['https://user:password@host.invalid', 'http://host.invalid/?key=x', 'file:///tmp/x'])
def test_secret_bearing_endpoint_refused(url):
    env = environment()
    env['IMMICH__URL'] = url
    with pytest.raises(c.Refused):
        c.registry_text(plan(), env)


def test_env_parser_never_executes(tmp_path):
    assert c.parse_env('A=$(touch dangerous)')['A'] == '$(touch dangerous)'
    for raw in ['export A=x', 'A=x\nA=y', 'A="unterminated', 'A="back\\slash"']:
        with pytest.raises(c.Refused):
            c.parse_env(raw)


def test_systemd_schedules_and_security():
    unit = (ROOT / 'deployment/systemd/pdi-p3c-writer@.service').read_text()
    assert all(x in unit for x in ('User=pdi', 'Group=pdi', 'NoNewPrivileges=true', 'KillMode=control-group'))
    assert 'Environment=PYTHONPATH=/opt/pdi/current/src' in unit
    start = next(x for x in unit.splitlines() if x.startswith('ExecStart='))
    assert all(x not in start for x in ('API', 'PASSWORD', 'DATABASE', 'principal', 'scope-id'))
    assert c.SCHEDULES == {'nextcloud-incremental': '*:0/5', 'nextcloud-full': '02:15',
                           'immich-incremental': '*:2/5', 'immich-daily': '05:15'}
    for name, calendar in c.SCHEDULES.items():
        timer = ops.timer_text(name)
        assert f'OnCalendar={calendar}' in timer
        assert f'Unit=pdi-p3c-writer@{name}.service' in timer
        assert 'Persistent=false' in timer
    assert not any(x in ' '.join(c.PIPELINES) for x in ('gmail', 'integration', 'enrichment'))


@pytest.mark.parametrize('fail', [None, DAILY[0], DAILY[1], DAILY[2]])
def test_daily_chain_stops_on_failure(fail):
    seen = []
    def run(principal, key, **kwargs):
        seen.append(key)
        assert principal == 'synthetic'
        if key == fail:
            raise RuntimeError('synthetic-failure')
        return 0
    runner = SimpleNamespace(run=run)
    if fail:
        with pytest.raises(RuntimeError):
            execute(runner, 'synthetic', 'immich.daily', 0)
        assert seen == list(DAILY[:DAILY.index(fail)+1])
    else:
        assert execute(runner, 'synthetic', 'immich.daily', 0) == 0
        assert seen == list(DAILY)


def baseline():
    return {'frozen': {'legacy': 'synthetic-fingerprint'}, 'source_ids': ['synthetic-id:scope'],
            'counts': dict.fromkeys(c.COUNT_KEYS, 2), 'states': {'scope': 1}, 'ledger': {}}


class FakeHost:
    """Exclusive fake production state; assert lock ownership at every action."""
    def __init__(self, tmp_path, fail=None):
        self.paths = SimpleNamespace(current=tmp_path / 'current')
        self.paths.current.symlink_to('previous-release')
        self.sha = 'c'*40
        self.enabled = False
        self.scheduled = False
        self.controlled = self.locked = False
        self.journal = None
        self.events = []
        self.fail = fail
        self.value = baseline()
        self.db = self
        self.context = 'synthetic-context'

    def context_fingerprint(self):
        return self.context

    @contextmanager
    def control(self):
        if self.controlled:
            raise c.Refused('CUTOVER_ALREADY_RUNNING')
        self.controlled = True
        try:
            yield
        finally:
            self.controlled = False

    @contextmanager
    def sync(self):
        assert self.controlled and not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def preflight(self):
        assert self.locked
        c.require(self.journal is None, 'APPLY_ALREADY_ATTEMPTED')
        if self.fail in ('ALEMBIC_MISMATCH', 'RELEASE_SHA', 'LEGACY_TIMER_ENABLED', 'ROLLBACK_METADATA_MISSING'):
            raise c.Refused(self.fail)

    def evidence(self, *, enabled, expected_counts=None):
        assert self.locked and enabled == self.enabled
        return deepcopy(self.value)

    compare = staticmethod(Database.compare)

    def set_enabled(self, enabled):
        assert self.locked
        self.enabled = enabled
        self.events.append(('identities', enabled))

    def verify_disabled(self):
        assert self.locked and not self.enabled

    def save(self, state):
        self.journal = deepcopy(state)

    def install(self):
        assert self.locked
        self.events.append(('install',))
        if self.fail == 'install':
            raise c.Refused('INSTALL')

    def verify_files(self):
        assert self.locked

    def health(self):
        assert self.locked
        self.events.append(('legacy-stays-disabled',))

    def qualify(self, instance):
        assert self.controlled and not self.locked
        with self.sync():  # fake systemd child owns SAME sync lock
            self.events.append(('qualify', instance))
            if self.fail == instance:
                raise c.Refused('QUALIFICATION')
            self.value['ledger'][instance] = [c.PIPELINES[instance], 'completed']
            self.value['states']['scope'] += 1
            if self.fail == 'invariant':
                self.value['frozen']['legacy'] = 'changed'

    def schedules(self, enabled):
        assert self.locked
        self.scheduled = enabled
        self.events.append(('schedule', enabled))
        if self.fail == 'schedule':
            raise c.Refused('SCHEDULE')

    def verify_schedules(self):
        assert self.locked and self.scheduled

    def verify_schedules_off(self):
        assert self.locked and not self.scheduled

    def stop(self):
        assert not self.locked
        self.scheduled = False
        self.events.append(('stop-scoped-only',))

    def read_state(self):
        return deepcopy(self.journal)


def test_entire_apply_rehearsal_and_verify(tmp_path):
    h = FakeHost(tmp_path)
    runner = ops.Cutover(h, {})
    assert runner.apply() == 'PASS'
    assert h.enabled and h.scheduled and h.journal['phase'] == 'PASS'
    assert [x[1] for x in h.events if x[0] == 'qualify'] == list(c.QUALIFICATION)
    assert h.events.index(('install',)) < h.events.index(('identities', True))
    runner.verify()
    with pytest.raises(c.Refused, match='APPLY_ALREADY_ATTEMPTED'):
        runner.apply()
    assert h.enabled and h.scheduled  # rerun refusal does not alter successful state


@pytest.mark.parametrize('failure', ['install', *c.QUALIFICATION, 'invariant', 'schedule'])
def test_partial_failure_is_fail_closed_no_legacy_restart(tmp_path, failure):
    h = FakeHost(tmp_path, failure)
    with pytest.raises(c.Refused):
        ops.Cutover(h, {}).apply()
    assert not h.enabled and not h.scheduled
    assert h.journal['phase'] == 'ABORTED'
    assert ('stop-scoped-only',) in h.events
    if failure != 'schedule':
        assert ('schedule', True) not in h.events
    assert not any('legacy-enable' in str(x) for x in h.events)


@pytest.mark.parametrize('failure', ['ALEMBIC_MISMATCH', 'RELEASE_SHA', 'LEGACY_TIMER_ENABLED', 'ROLLBACK_METADATA_MISSING'])
def test_preflight_failure_has_no_mutation(tmp_path, failure):
    h = FakeHost(tmp_path, failure)
    with pytest.raises(c.Refused, match=failure):
        ops.Cutover(h, {}).apply()
    assert h.events == [] and h.journal is None


def test_second_apply_control_lock_refused(tmp_path):
    h = FakeHost(tmp_path)
    with h.control():
        with pytest.raises(c.Refused, match='CUTOVER_ALREADY_RUNNING'):
            ops.Cutover(h, {}).apply()
    assert h.events == []


def test_abort_cleanup_failure_not_reported_safe(tmp_path):
    h = FakeHost(tmp_path, 'immich-person')
    h.stop = lambda: (_ for _ in ()).throw(OSError('synthetic-stop-failure'))
    with pytest.raises(c.Refused, match='ABORT_INCOMPLETE'):
        ops.Cutover(h, {}).apply()
    assert not h.enabled
    assert h.journal['phase'] == 'ABORT_INCOMPLETE'


def test_atomic_symlink_replacement(tmp_path, monkeypatch):
    link = tmp_path / 'current'
    link.symlink_to('old')
    real = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda p: SimpleNamespace(st_uid=0, st_mode=real(p).st_mode))
    calls = []
    replace = os.replace
    def record(source, target):
        assert link.is_symlink() and os.readlink(link) == 'old'
        calls.append((source, target))
        replace(source, target)
    monkeypatch.setattr(os, 'replace', record)
    ops.atomic_symlink(link, 'new')
    assert os.readlink(link) == 'new' and len(calls) == 1


@pytest.mark.parametrize('change', ['frozen', 'source_ids', 'ledger', 'states', 'counts'])
def test_post_qualification_invariant_regressions(change):
    before = baseline()
    before['ledger']['old'] = ['prior', 'completed']
    after = deepcopy(before)
    if change in ('frozen', 'states', 'ledger'):
        after[change] = {}
    elif change == 'source_ids':
        after[change] = []
    else:
        after['counts']['resource_enrichments'] += 1
    with pytest.raises(c.Refused):
        Database.compare(before, after)


def test_ledger_must_be_exact_new_success():
    before = baseline()
    after = deepcopy(before)
    after['ledger']['new'] = ['person.immich.sync', 'failed']
    with pytest.raises(c.Refused, match='QUALIFICATION_LEDGER'):
        Database.compare(before, after, 'person.immich.sync')


def test_cli_secret_errors_sanitized(capsys):
    result = ops.main(['apply', '--release', '/synthetic/release', '--expected-sha', 'c'*40,
        '--production-host', 'synthetic', '--rollback-snapshot', 'a'*64,
        '--rollback-source-sha', 'b'*40, '--expected-counts', 'synthetic-secret'])
    assert result == 1
    output = capsys.readouterr()
    assert 'synthetic-secret' not in output.out + output.err
    assert 'NOT_CONFIRMED' in output.out


def test_subprocess_failure_never_echoes_output(monkeypatch):
    monkeypatch.setattr(ops.subprocess, 'run', lambda *a, **k:
                        SimpleNamespace(returncode=1, stdout='synthetic-secret', stderr='synthetic-secret'))
    with pytest.raises(c.Refused, match='^COMMAND_FAILED$'):
        ops.command(['synthetic'])


def test_real_flock_control_exclusion_and_child_handoff(tmp_path, monkeypatch):
    paths = replace(ops.Paths(), control=tmp_path / 'control.lock', sync=tmp_path / 'sync.lock')
    paths.sync.touch()
    h = ops.Host(paths, tmp_path, 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    original = os.fstat
    monkeypatch.setattr(os, 'fstat', lambda fd: SimpleNamespace(st_uid=0, st_mode=original(fd).st_mode))
    with h.control():
        with pytest.raises(c.Refused, match='CUTOVER_ALREADY_RUNNING'):
            with h.control():
                pass
        with h.sync():
            pass
        # A separate interpreter (like systemd) can now acquire the same lock.
        result = subprocess.run([sys.executable, '-c',
            'from pathlib import Path; from pdi.operational import acquire_formal_lock; import sys; '
            'lock=acquire_formal_lock(Path(sys.argv[1]), 0); lock.__enter__(); lock.__exit__(None,None,None)',
            str(paths.sync)], capture_output=True, timeout=10)
        assert result.returncode == 0
        with h.sync():
            pass


@pytest.mark.parametrize('kind', ['timer', 'service'])
def test_actual_host_health_refuses_legacy_activity(kind):
    h = ops.Host(ops.Paths(), Path('/synthetic'), 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    def props(unit):
        if unit in c.READ_SERVICES + c.BACKUP_TIMERS:
            return {'ActiveState': 'active', 'UnitFileState': 'enabled'}
        if unit == c.LEGACY[0] + '.' + kind:
            return {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'disabled'}
        return {'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'disabled'}
    h.properties = props
    with pytest.raises(c.Refused, match='WRITER_NOT_QUIET'):
        h.health()


def test_actual_host_preflight_wrong_release_sha(tmp_path, monkeypatch):
    release = tmp_path / ('c'*40)
    release.mkdir()
    h = ops.Host(replace(ops.Paths(), releases=tmp_path), release, 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    monkeypatch.setattr(ops, 'command', lambda argv: 'd'*40)
    with pytest.raises(c.Refused, match='RELEASE_SHA'):
        h.preflight()


@pytest.fixture
def host_inventory_preflight(tmp_path, monkeypatch):
    """Actual Host.preflight/health and command(), with no host commands/DB.

    Only ownership is simulated for temporary files. The subprocess boundary
    returns synthetic inventory; every attempted command must be read-only.
    """
    releases = tmp_path / 'releases'
    release = releases / ('c' * 40)
    release.mkdir(parents=True)
    old = releases / 'old'
    old.mkdir()
    current = tmp_path / 'current'
    current.symlink_to(old)
    recovery = tmp_path / 'recovery'
    recovery.mkdir()
    (recovery / 'final-premigration.env').write_text(''.join(k + '=' + v + '\n' for k, v in rollback().items()))
    (recovery / 'final-premigration.env').chmod(0o600)
    (recovery / 'FINAL-PREMIGRATION.md').write_text('Synthetic recovery evidence')
    paths = replace(ops.Paths(), releases=releases, current=current, recovery=recovery,
                    config=tmp_path / 'config', state=tmp_path / 'state', units=tmp_path / 'units')
    h = ops.Host(paths, release, 'c' * 40, 'synthetic', 'a' * 64, 'b' * 40)
    for name in ('stat', 'lstat'):
        original = getattr(Path, name)
        def root_stat(path, *args, _original=original, **kwargs):
            result = list(_original(path, *args, **kwargs))
            result[0] &= ~0o022
            result[4] = result[5] = 0
            return os.stat_result(result)
        monkeypatch.setattr(Path, name, root_stat)
    original_iterdir = Path.iterdir
    monkeypatch.setattr(Path, 'iterdir', lambda path: iter(()) if path == Path('/proc') else original_iterdir(path))
    responses = {'unit_files': '', 'unit_files_rc': 0, 'units': '', 'units_rc': 0}
    calls = []
    def subprocess_run(argv, **kwargs):
        calls.append(argv)
        assert kwargs['capture_output'] is True
        assert kwargs['env'] == {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'GIT_OPTIONAL_LOCKS': '0'}
        rc = 0
        if argv == ['git', '-C', str(release), 'rev-parse', 'HEAD']:
            output = h.sha
        elif argv == ['git', '-C', str(release), 'status', '--porcelain', '--untracked-files=all']:
            output = ''
        elif argv[:2] == ['systemctl', 'show']:
            unit = argv[2]
            if unit in c.READ_SERVICES + c.BACKUP_TIMERS:
                output = 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled'
            elif any(unit == prefix + suffix for prefix in c.LEGACY for suffix in ('.service', '.timer')):
                output = 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled'
            else:
                assert unit.startswith('pdi-p3c-')
                output = 'LoadState=not-found\nActiveState=inactive'
        elif argv == ['systemctl', 'list-unit-files', '--no-legend', '--no-pager']:
            output, rc = responses['unit_files'], responses['unit_files_rc']
        elif argv == ['systemctl', 'list-units', '--all', '--plain', '--no-legend', 'pdi-scoped*', 'pdi-p3c*']:
            output, rc = responses['units'], responses['units_rc']
        else:
            pytest.fail('unexpected or mutating preflight command')
        return SimpleNamespace(returncode=rc, stdout=output, stderr='synthetic-hidden-stderr')
    monkeypatch.setattr(ops.subprocess, 'run', subprocess_run)
    def no_mutation(*args, **kwargs):
        pytest.fail('preflight attempted mutation or DB connection')
    for name in ('atomic_write', 'atomic_symlink', 'create_postgres_engine'):
        monkeypatch.setattr(ops, name, no_mutation)
    def snapshot():
        return {str(p.relative_to(tmp_path)): ('link', os.readlink(p)) if p.is_symlink() else ('file', p.read_bytes())
                for p in tmp_path.rglob('*') if p.is_symlink() or p.is_file()}
    before = snapshot()
    yield h, responses, calls
    assert snapshot() == before
    assert not paths.config.exists() and not paths.state.exists() and not paths.units.exists()
    assert h.db is None


@pytest.mark.parametrize('inventory', [
    '',
    'unrelated.timer enabled enabled\nother.service enabled-runtime disabled',
    'not-pdi-scoped.timer enabled enabled',
    'pdi-scoped@synthetic.service disabled enabled',
    'pdi-p3c-extra.timer disabled enabled',
    'pdi-scoped@.service static -',
    'pdi-p3c-extra.timer static -',
    'pdi-scoped-extra.timer masked enabled',
])
def test_preflight_accepts_empty_or_non_enabled_scoped_unit_inventory(host_inventory_preflight, inventory):
    h, responses, calls = host_inventory_preflight
    responses['unit_files'] = inventory
    h.preflight()
    assert ['systemctl', 'list-unit-files', '--no-legend', '--no-pager'] in calls
    assert ['systemctl', 'list-units', '--all', '--plain', '--no-legend', 'pdi-scoped*', 'pdi-p3c*'] in calls


@pytest.mark.parametrize('prefix', ['pdi-scoped', 'pdi-p3c'])
@pytest.mark.parametrize('state', ['enabled', 'enabled-runtime'])
def test_preflight_refuses_enabled_scoped_unit_inventory(host_inventory_preflight, prefix, state):
    h, responses, _ = host_inventory_preflight
    responses['unit_files'] = f'{prefix}-extra.timer {state} disabled'
    with pytest.raises(c.Refused, match='^OTHER_SCOPED_SCHEDULE$'):
        h.preflight()


@pytest.mark.parametrize('inventory', ['', 'pdi-scoped-extra.timer disabled disabled'])
def test_preflight_inventory_command_failure_is_fatal(host_inventory_preflight, inventory):
    h, responses, _ = host_inventory_preflight
    responses.update(unit_files=inventory, unit_files_rc=1)
    with pytest.raises(c.Refused, match='^COMMAND_FAILED$'):
        h.preflight()


def test_preflight_refuses_malformed_matching_inventory(host_inventory_preflight):
    h, responses, _ = host_inventory_preflight
    responses['unit_files'] = 'pdi-scoped-extra.timer'
    with pytest.raises(c.Refused, match='^SCOPED_UNIT_INVENTORY_MALFORMED$'):
        h.preflight()


@pytest.mark.parametrize('prefix', ['pdi-scoped', 'pdi-p3c'])
@pytest.mark.parametrize('state', ['active', 'activating', 'deactivating'])
def test_preflight_retains_active_scoped_writer_refusal(host_inventory_preflight, prefix, state):
    h, responses, calls = host_inventory_preflight
    responses['units'] = f'{prefix}@synthetic.service loaded {state} running Synthetic writer'
    with pytest.raises(c.Refused, match='^OTHER_SCOPED_WRITER$'):
        h.preflight()
    assert not any(argv[:2] == ['systemctl', 'list-unit-files'] for argv in calls)


def test_preflight_retains_list_units_command_failure(host_inventory_preflight):
    h, responses, _ = host_inventory_preflight
    responses['units_rc'] = 1
    with pytest.raises(c.Refused, match='^COMMAND_FAILED$'):
        h.preflight()


class Result:
    def __init__(self, rows):
        self.rows = rows
    def mappings(self):
        return self.rows
    def scalars(self):
        return self
    def all(self):
        return self.rows


class SyntheticConnection:
    """Exercises every SQL verifier branch with synthetic relational responses."""
    def __init__(self, p, fault=None, enabled=False):
        self.p, self.fault, self.enabled = p, fault, enabled
        self.statements = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def begin(self):
        return self
    def scalar(self, statement, params=None):
        sql = str(statement)
        self.statements.append(sql)
        if sql.startswith('SHOW'):
            return '160014'
        if 'md5' in sql:
            return 'synthetic-fingerprint'
        if 'provider_sync_state l' in sql:
            return 1
        if self.fault == 'null' and 'IS NULL' in sql:
            return 1
        if self.fault == 'duplicate' and 'HAVING count(*)>1' in sql:
            return 1
        if self.fault == 'resource' and 'b.asset_id=r.resource_id' in sql:
            return 1
        if self.fault == 'person' and 's.person_id=r.person_id' in sql:
            return 1
        if self.fault == 'source-scope' and 'provider=:p' in sql:
            return 1
        if self.fault == 'derived' and ' EXCEPT ' in sql:
            return 1
        if sql in [f'SELECT count(*) FROM {t}' for t in c.COUNT_TABLES]:
            return 2
        if 'provider = :provider' in sql:
            return 2
        return 0
    def execute(self, statement, params=None):
        sql = str(statement)
        self.statements.append(sql)
        p = self.p
        if 'version_num' in sql:
            return Result(['wrong' if self.fault == 'alembic' else c.HEAD])
        if sql.endswith('FROM provider_instances'):
            return Result([{'id': p.instances[k], 'provider_type': k,
                'enabled': (self.enabled and k in c.MECHANISMS) or (self.fault == k)} for k in c.PROVIDERS])
        if sql.endswith('FROM provider_accounts'):
            return Result([{'id': p.accounts[k], 'provider_instance_id': p.instances[k],
                            'provider_native_id': 'wrong' if self.fault == 'native' else k,
                            'enabled': self.enabled} for k in c.MECHANISMS])
        if sql.endswith('FROM observation_scopes'):
            return Result([{'id': p.scopes[k], 'provider_instance_id': p.instances[k],
                            'provider_account_id': p.accounts.get(k), 'enabled': self.enabled and k in c.MECHANISMS} for k in c.PROVIDERS])
        if sql.endswith('FROM observation_scope_sync_state'):
            return Result([{'observation_scope_id': p.scopes[k], 'mechanism': m,
                            'version': 1, 'initialized': True, 'reconciliation_required': self.fault == 'state'}
                           for k, m in c.MECHANISMS.items()])
        if 'ORDER BY id' in sql:
            return Result(['synthetic-source:scope'])
        return Result([])


def test_database_verifier_readonly_and_exact_baseline():
    p = plan()
    connection = SyntheticConnection(p)
    db = Database(SimpleNamespace(connect=lambda: connection), p, {'nextcloud': 'nextcloud', 'immich': 'immich'})
    result = db.evidence(enabled=False, expected_counts=dict.fromkeys(c.COUNT_KEYS, 2))
    assert result['counts']['assets'] == 2
    assert connection.statements[0].endswith('READ ONLY')
    assert not any(s.startswith(('UPDATE', 'INSERT', 'DELETE')) for s in connection.statements)
    with pytest.raises(c.Refused, match='P3B_COUNTS_MISMATCH'):
        db.evidence(enabled=False, expected_counts=dict.fromkeys(c.COUNT_KEYS, 3))


@pytest.mark.parametrize('fault,code', [
    ('alembic', 'ALEMBIC_MISMATCH'), ('gmail', 'INSTANCE_MISMATCH'), ('integration-test', 'INSTANCE_MISMATCH'),
    ('native', 'ACCOUNT_MISMATCH'), ('null', 'NULL_SOURCE_SCOPE'), ('duplicate', 'DUPLICATE_SOURCE'),
    ('resource', 'RELATION_RESOURCE_EVIDENCE'), ('person', 'RELATION_PERSON_EVIDENCE'),
    ('source-scope', 'SOURCE_WRONG_SCOPE'), ('derived', 'P3B_DERIVED_NOT_EQUIVALENT'), ('state', 'STATE_NOT_READY'),
])
def test_database_verifier_refusals(fault, code):
    p = plan()
    connection = SyntheticConnection(p, fault)
    db = Database(SimpleNamespace(connect=lambda: connection), p, {'nextcloud': 'nextcloud', 'immich': 'immich'})
    with pytest.raises(c.Refused, match=code):
        db.evidence(enabled=False, expected_counts=dict.fromkeys(c.COUNT_KEYS, 2))


@pytest.mark.parametrize('enabled', [True, False])
def test_identity_enable_disable_transaction_exact_targets(enabled):
    p = plan()
    calls = []
    @contextmanager
    def begin():
        calls.append('begin')
        yield SimpleNamespace(execute=lambda sql, params: (calls.append((str(sql), params)) or SimpleNamespace(rowcount=1)))
        calls.append('commit')
    db = Database(SimpleNamespace(begin=begin), p, {})
    db.set_enabled(enabled)
    assert calls[0] == 'begin' and calls[-1] == 'commit'
    statements = calls[1:-1]
    assert len(statements) == 6
    assert all(params['e'] == enabled for _, params in statements)
    assert {params['id'] for _, params in statements} == {p.instances[k] for k in c.MECHANISMS} | set(p.accounts.values()) | {p.scopes[k] for k in c.MECHANISMS}
    assert ('provider_instances' if enabled else 'observation_scopes') in statements[0][0]


@pytest.mark.parametrize('umask', [0o022, 0o077])
def test_real_install_in_temp_filesystem_with_fake_systemctl(tmp_path, monkeypatch, umask):
    release = tmp_path / 'release'
    target = release / 'deployment/systemd'
    target.mkdir(parents=True)
    (target / 'pdi-p3c-writer@.service').write_text((ROOT / 'deployment/systemd/pdi-p3c-writer@.service').read_text())
    units = tmp_path / 'systemd'
    units.mkdir()
    current = tmp_path / 'current'
    current.symlink_to('previous-release')
    paths = replace(ops.Paths(), config=tmp_path / 'config', units=units, current=current)
    h = ops.Host(paths, release, 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    h.plan, h.env = plan(), environment()
    commands, ownership = [], []
    monkeypatch.setattr(ops, 'command', lambda argv: commands.append(argv))
    monkeypatch.setattr(ops.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_gid=4321))
    monkeypatch.setattr(os, 'chown', lambda path, uid, gid: ownership.append((str(path), uid, gid)))
    monkeypatch.setattr(os, 'fchown', lambda fd, uid, gid: ownership.append(('fd', uid, gid)))
    original = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda p: SimpleNamespace(st_uid=0, st_mode=original(p).st_mode))
    h.properties = lambda unit: {'User': 'pdi', 'Group': 'pdi', 'NoNewPrivileges': 'yes', 'DropInPaths': '',
                                'FragmentPath': str(units / 'pdi-p3c-writer@.service')}
    old_umask = os.umask(umask)
    try:
        h.install()
    finally:
        os.umask(old_umask)
    assert current.resolve() == release
    assert (paths.config / 'registry.toml').stat().st_mode & 0o777 == 0o640
    assert paths.config.stat().st_mode & 0o777 == 0o750
    for name in c.PIPELINES:
        assert (paths.config / 'units' / (name + '.env')).stat().st_mode & 0o777 == 0o600
    assert ('fd', 0, 4321) in ownership and ('fd', 0, 0) in ownership
    assert ['systemctl', 'daemon-reload'] in commands
    assert not any('enable' in argv or 'start' in argv for argv in commands)
    assert {x.name for x in units.glob('*.timer')} == {f'pdi-p3c-{i}.timer' for i in c.SCHEDULES}
    for argv in commands:
        assert all(value not in ' '.join(argv) for value in environment().values())


def test_stop_attempts_every_scoped_unit_even_if_one_stop_fails(monkeypatch):
    h = ops.Host(ops.Paths(), Path('/synthetic'), 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    h.properties = lambda _: {'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'disabled'}
    calls = []
    def cmd(argv, **kwargs):
        calls.append(argv)
        if argv == ['systemctl', 'stop', 'pdi-p3c-nextcloud-full.timer']:
            raise c.Refused('COMMAND_FAILED')
    monkeypatch.setattr(ops, 'command', cmd)
    with pytest.raises(c.Refused, match='ABORT_STOP_FAILED'):
        h.stop()
    assert ['systemctl', 'stop', 'pdi-p3c-writer@immich-relation.service'] in calls
    assert all(not any(prefix in x for prefix in c.LEGACY) for argv in calls for x in argv)


def test_stale_aborted_journal_cannot_confirm_current_failure(monkeypatch, capsys):
    h = SimpleNamespace(db=None, read_state=lambda: {'phase': 'ABORTED'},
        load=lambda: (_ for _ in ()).throw(c.Refused('CURRENT_PREFLIGHT_FAILED')))
    monkeypatch.setattr(ops, 'Host', lambda *args: h)
    result = ops.main(['verify', '--release', str(ROOT), '--expected-sha', 'c'*40,
        '--production-host', 'synthetic', '--rollback-snapshot', 'a'*64,
        '--rollback-source-sha', 'b'*40,
        '--expected-counts', ','.join(k + '=2' for k in c.COUNT_KEYS)])
    assert result == 1
    output = capsys.readouterr().out
    assert 'INGESTION_PAUSED=NOT_CONFIRMED' in output
    assert 'SCOPED_WRITER_PRODUCTION_ENABLED=NOT_CONFIRMED' in output


def test_abort_plan_drift_refuses_wrong_target_database_mutation(tmp_path):
    h = FakeHost(tmp_path)
    runner = ops.Cutover(h, {})
    runner.apply()
    state = h.read_state()
    h.context = 'different-principal-or-database'
    with h.control(), pytest.raises(c.Refused, match='ABORT_INCOMPLETE'):
        runner.abort(state)
    assert ('identities', False) not in h.events
    assert not h.scheduled and not runner.abort_confirmed
    assert h.journal['phase'] == 'ABORT_INCOMPLETE'


def test_abort_requires_fresh_database_readback(tmp_path):
    h = FakeHost(tmp_path, 'immich-person')
    h.verify_disabled = lambda: (_ for _ in ()).throw(c.Refused('ABORT_IDENTITIES_NOT_DISABLED'))
    runner = ops.Cutover(h, {})
    with pytest.raises(c.Refused, match='ABORT_INCOMPLETE'):
        runner.apply()
    assert not runner.abort_confirmed and h.journal['phase'] == 'ABORT_INCOMPLETE'


@pytest.mark.parametrize('fault', [None, 'gmail', 'integration-test'])
def test_database_abort_readback_includes_preservation_providers(fault):
    p = plan()
    connection = SyntheticConnection(p, fault)
    db = Database(SimpleNamespace(connect=lambda: connection), p, {})
    if fault:
        with pytest.raises(c.Refused, match='ABORT_IDENTITIES_NOT_DISABLED'):
            db.verify_disabled()
    else:
        db.verify_disabled()
    assert not any('checkpoint' in sql or 'pipeline_runs' in sql for sql in connection.statements)


def test_stop_does_not_trust_successful_disable_exit_code(monkeypatch):
    h = ops.Host(ops.Paths(), Path('/synthetic'), 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    h.properties = lambda _: {'LoadState': 'loaded', 'ActiveState': 'inactive', 'UnitFileState': 'enabled'}
    monkeypatch.setattr(ops, 'command', lambda *a, **k: '')
    with pytest.raises(c.Refused, match='ABORT_STOP_FAILED'):
        h.stop()


@pytest.mark.parametrize('error', [KeyboardInterrupt, TimeoutError, RuntimeError])
def test_qualification_exception_releases_lock_before_abort(tmp_path, error):
    h = FakeHost(tmp_path)
    h.qualify = lambda _: (_ for _ in ()).throw(error())
    runner = ops.Cutover(h, {})
    with pytest.raises(error):
        runner.apply()
    assert runner.abort_confirmed and not h.enabled and not h.scheduled


def test_identity_enable_partial_failure_enters_cleanup(tmp_path):
    h = FakeHost(tmp_path)
    original = h.set_enabled
    def partial(enabled):
        original(enabled)
        if enabled:
            raise RuntimeError('synthetic-transaction-error')
    h.set_enabled = partial
    runner = ops.Cutover(h, {})
    with pytest.raises(RuntimeError):
        runner.apply()
    assert not h.enabled and not h.scheduled and runner.abort_confirmed


def test_journal_failure_cannot_confirm_abort(tmp_path):
    h = FakeHost(tmp_path)
    runner = ops.Cutover(h, {})
    runner.apply()
    h.save = lambda _: (_ for _ in ()).throw(OSError('synthetic-disk-failure'))
    with h.control(), pytest.raises(OSError):
        runner.abort(h.read_state())
    assert not runner.abort_confirmed


def test_context_fingerprint_binds_route_without_password(tmp_path):
    h = ops.Host(ops.Paths(), tmp_path, 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    h.plan, h.env = plan(), environment()
    first = h.context_fingerprint()
    h.env['DATABASE__URL'] = h.env['DATABASE__URL'].replace('synthetic-db-secret', 'rotated-secret')
    assert h.context_fingerprint() == first
    h.env['DATABASE__URL'] += '_different'
    assert h.context_fingerprint() != first


def test_premature_timer_activation_refused():
    h = ops.Host(ops.Paths(), Path('/synthetic'), 'c'*40, 'synthetic', 'a'*64, 'b'*40)
    h.properties = lambda _: {'UnitFileState': 'enabled', 'ActiveState': 'inactive'}
    with pytest.raises(c.Refused, match='PREMATURE_SCHEDULE'):
        h.verify_schedules_off()


def test_all_generated_units_with_systemd_analyze(tmp_path):
    analyzer = shutil.which('systemd-analyze')
    if analyzer is None:
        pytest.skip('systemd-analyze unavailable; no static verification PASS')
    # Offline disposable root: exact unit bytes, inert dependencies/executable.
    # Does not load/reload/start any host service.
    units = tmp_path / 'etc/systemd/system'
    units.mkdir(parents=True)
    service = 'pdi-p3c-writer@.service'
    (units / service).write_text((ROOT / 'deployment/systemd' / service).read_text())
    names = [service]
    for instance in c.SCHEDULES:
        name = f'pdi-p3c-{instance}.timer'
        (units / name).write_text(ops.timer_text(instance))
        names.append(name)
    for name in ('sysinit', 'basic', 'shutdown', 'timers', 'network-online'):
        (units / (name + '.target')).write_text('[Unit]\nDescription=Synthetic target\n')
    executable = tmp_path / 'opt/pdi/current/.venv/bin/python'
    executable.parent.mkdir(parents=True)
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    result = subprocess.run([analyzer, '--root=' + str(tmp_path), '--generators=no', '--man=no',
                             'verify', *names], capture_output=True, text=True, timeout=30)
    if 'SO_PASSCRED failed: Operation not permitted' in result.stderr:
        pytest.skip('sandbox denies systemd SO_PASSCRED; static verification NOT executed')
    assert result.returncode == 0, result.stderr
