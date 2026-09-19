"""Human-authorized P3C operations. Imports have no operational side effects."""

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import tomllib
from sqlalchemy.engine import make_url

from pdi.database import create_postgres_engine
from pdi.operational import acquire_formal_lock
from pdi.scoped_operator_config import load_scoped_operator_configuration
from .contracts import (BACKUP_TIMERS, COUNT_KEYS, LEGACY, PIPELINES, QUALIFICATION,
                        READ_SERVICES, SCHEDULES, Plan, Refused, parse_env, registry_text,
                        require, unit_environment, validate_rollback)
from .database import Database


@dataclass(frozen=True)
class Paths:
    """Fixed production paths; tests inject an entirely separate filesystem."""
    staging: Path = Path('/etc/pdi/scoped-staging')
    env: Path = Path('/etc/pdi/pdi.env')
    recovery: Path = Path('/etc/pdi-backup-recovery/pdi-core')
    config: Path = Path('/etc/pdi/scoped')
    units: Path = Path('/etc/systemd/system')
    current: Path = Path('/opt/pdi/current')
    releases: Path = Path('/opt/pdi/releases')
    state: Path = Path('/var/lib/pdi-p3c')
    control: Path = Path('/run/lock/pdi-mu13-p3c-cutover.lock')
    sync: Path = Path('/run/lock/pdi-sync.lock')


def secure_file(path, *, exact_mode=None, private=True):
    """Refuse symlinks, non-root owners and writable ancestors before reading."""
    require(path.is_absolute(), 'PATH_NOT_ABSOLUTE')
    for item in [path, *path.parents]:
        s = item.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'UNTRUSTED_PATH')
    s = path.stat()
    require(stat.S_ISREG(s.st_mode) and (not private or not s.st_mode & 0o007), 'UNPROTECTED_INPUT')
    if exact_mode is not None:
        require(stat.S_IMODE(s.st_mode) == exact_mode and s.st_gid == 0, 'INPUT_PERMISSIONS')
    return path.read_text()


def atomic_write(path, content, *, gid=0, mode=0o600):
    require(not path.is_symlink(), 'WRITE_SYMLINK')
    fd, name = tempfile.mkstemp(prefix='.p3c-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchown(f.fileno(), 0, gid)
            os.fchmod(f.fileno(), mode)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def atomic_symlink(path, target):
    require(path.is_symlink() and path.lstat().st_uid == 0, 'CURRENT_NOT_ROOT_SYMLINK')
    fd, temporary = tempfile.mkstemp(prefix='.p3c-link-', dir=path.parent)
    os.close(fd)
    os.unlink(temporary)
    try:
        os.symlink(str(target), temporary)
        os.replace(temporary, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def command(argv, *, timeout=60):
    # Never print stdout/stderr or exceptions from subprocesses.
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                 'GIT_OPTIONAL_LOCKS': '0'})
    require(result.returncode == 0, 'COMMAND_FAILED')
    return result.stdout.strip()


def timer_text(instance):
    return (f'[Unit]\nDescription=PDI scoped schedule ({instance})\n\n[Timer]\n'
            f'OnCalendar={SCHEDULES[instance]}\nPersistent=false\nAccuracySec=1s\n'
            f'Unit=pdi-p3c-writer@{instance}.service\n\n[Install]\nWantedBy=timers.target\n')


class Host:
    def __init__(self, paths, release, expected_sha, production_host, snapshot, source_sha):
        self.paths, self.release, self.sha = paths, release, expected_sha
        self.production_host, self.snapshot, self.source_sha = production_host, snapshot, source_sha
        self.plan = self.env = self.db = None

    def load(self):
        require(os.geteuid() == 0 and socket.gethostname() == self.production_host, 'HOST_OR_PRIVILEGE')
        require(bool(self.production_host) and re.fullmatch('[0-9a-f]{40}', self.sha), 'RELEASE_ARGUMENT')
        p = self.paths
        self.plan = Plan.parse(tomllib.loads(secure_file(p.staging / 'identity-plan.toml')),
                               tomllib.loads(secure_file(p.staging / 'transition-plan.toml')))
        self.env = parse_env(secure_file(p.env))
        native = parse_env(secure_file(p.staging / 'provider-native-ids.conf'))
        require(set(native) == {'NEXTCLOUD_PROVIDER_NATIVE_ID', 'IMMICH_PROVIDER_NATIVE_ID'} and all(native.values()), 'NATIVE_ID_PLAN')
        registry_text(self.plan, self.env)  # validates all config input without logging
        # Resolve through the actual router, even for administrative evidence.
        from pdi.principal import PrincipalRegistry, DatabaseBindingRegistry, PrincipalDatabaseRouter
        raw = tomllib.loads(registry_text(self.plan, self.env))
        router = PrincipalDatabaseRouter(PrincipalRegistry.from_mapping(raw), DatabaseBindingRegistry.from_mapping(raw, self.env))
        self.db = Database(create_postgres_engine(router.resolve(self.plan.principal).database_url), self.plan,
                           {k: native[k.upper() + '_PROVIDER_NATIVE_ID'] for k in ('nextcloud', 'immich')})

    @contextmanager
    def control(self):
        # New root-only file. O_NOFOLLOW prevents a privileged symlink write.
        fd = os.open(self.paths.control, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            s = os.fstat(fd)
            require(s.st_uid == 0 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600, 'CONTROL_LOCK_PERMISSIONS')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('CUTOVER_ALREADY_RUNNING') from None
            yield
        finally:
            os.close(fd)

    def sync(self):
        require(not self.paths.sync.is_symlink() and self.paths.sync.is_file(), 'SYNC_LOCK_MISSING')
        return acquire_formal_lock(self.paths.sync, 300)

    def properties(self, unit):
        raw = command(['systemctl', 'show', unit, '--property=LoadState,ActiveState,UnitFileState,SubState,Result,ExecMainStatus,User,Group,NoNewPrivileges,FragmentPath,DropInPaths'])
        return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)

    def quiet(self, unit, *, missing=False):
        s = self.properties(unit)
        require((missing and s.get('LoadState') == 'not-found') or
                (s.get('LoadState') in {'loaded', 'masked'} and s.get('ActiveState') in {'inactive', 'failed'}), 'WRITER_NOT_QUIET')
        return s

    def health(self):
        for unit in READ_SERVICES + BACKUP_TIMERS:
            s = self.properties(unit)
            require(s.get('ActiveState') == 'active', 'COMPATIBILITY_SERVICE_UNHEALTHY')
            if unit in BACKUP_TIMERS:
                require(s.get('UnitFileState') == 'enabled', 'BACKUP_TIMER_NOT_ENABLED')
        for prefix in LEGACY:
            s = self.quiet(prefix + '.timer')
            require(s.get('UnitFileState') == 'disabled' and s.get('ActiveState') == 'inactive', 'LEGACY_TIMER_ENABLED')
            self.quiet(prefix + '.service')
        # Detect direct legacy CLI invocations outside systemd, without printing argv.
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                args = (proc / 'cmdline').read_bytes().split(b'\0')
            except FileNotFoundError:
                continue
            modules = {b'pdi.main', b'pdi.enrichment', b'pdi.person_identity', b'pdi.resource_person_relation', b'pdi.operational', b'pdi.scoped_operational'}
            require(not any(a == b'-m' and i+1 < len(args) and args[i+1] in modules for i, a in enumerate(args)), 'LEGACY_PROCESS_RUNNING')
            require(not any(a.rsplit(b'/', 1)[-1] == b'pdi' and i+1 < len(args) and args[i+1] == b'sync'
                            for i, a in enumerate(args)), 'LEGACY_PROCESS_RUNNING')

    def preflight(self):
        p = self.paths
        require(self.release.is_absolute() and self.release == self.release.resolve() and
                self.release.parent == p.releases and self.release.name == self.sha, 'RELEASE_PATH')
        require(command(['git', '-C', str(self.release), 'rev-parse', 'HEAD']) == self.sha, 'RELEASE_SHA')
        require(command(['git', '-C', str(self.release), 'status', '--porcelain', '--untracked-files=all']) == '', 'RELEASE_DIRTY')
        # Verify actual runtime source and all installed dependencies are immutable
        # to the service account. Do not chmod/chown a release to make it pass.
        for directory, dirs, files in os.walk(self.release, followlinks=False):
            for name in ['.', *dirs, *files]:
                item = Path(directory) / name
                s = item.stat()
                require(s.st_uid == 0 and not s.st_mode & 0o022, 'RELEASE_MUTABLE')
                if item.is_symlink():
                    for parent in item.resolve().parents:
                        owner = parent.stat()
                        require(owner.st_uid == 0 and not owner.st_mode & 0o022, 'RELEASE_SYMLINK_TARGET_MUTABLE')
        for item in [p.releases, *p.releases.parents]:
            s = item.stat()
            require(s.st_uid == 0 and not s.st_mode & 0o022, 'RELEASE_PARENT_MUTABLE')
        require(p.current.is_symlink() and p.current.exists(), 'CURRENT_NOT_SYMLINK')
        require(p.current.lstat().st_uid == 0, 'CURRENT_OWNER')
        recovery = parse_env(secure_file(p.recovery / 'final-premigration.env', exact_mode=0o600))
        validate_rollback(recovery, self.snapshot, self.source_sha)
        require(recovery['SOURCE_HOST'] == self.production_host, 'ROLLBACK_SOURCE_HOST')
        require(bool(secure_file(p.recovery / 'FINAL-PREMIGRATION.md', private=False)), 'ROLLBACK_DOCUMENT_MISSING')
        require(not p.config.exists() and not p.config.is_symlink(), 'SCOPED_CONFIG_ALREADY_EXISTS')
        require(not p.state.exists() and not p.state.is_symlink(), 'APPLY_ALREADY_ATTEMPTED')
        for instance in PIPELINES:
            require(self.properties(f'pdi-p3c-writer@{instance}.service').get('LoadState') == 'not-found', 'WRITER_ALREADY_INSTALLED')
        for instance in SCHEDULES:
            require(self.properties(f'pdi-p3c-{instance}.timer').get('LoadState') == 'not-found', 'SCHEDULE_ALREADY_INSTALLED')
        require(not (p.units / 'pdi-p3c-writer@.service').exists(), 'UNIT_ALREADY_INSTALLED')
        # Other scoped units must not be enabled or running before P3C.
        for line in command(['systemctl', 'list-units', '--all', '--plain', '--no-legend', 'pdi-scoped*', 'pdi-p3c*']).splitlines():
            require(not re.search(r'\s(active|activating|deactivating)\s', line), 'OTHER_SCOPED_WRITER')
        for line in command(['systemctl', 'list-unit-files', '--no-legend', 'pdi-scoped*', 'pdi-p3c*']).splitlines():
            require(not re.search(r'\s(enabled|enabled-runtime)\s', line), 'OTHER_SCOPED_SCHEDULE')
        self.health()

    def save(self, state):
        if not self.paths.state.exists():
            self.paths.state.mkdir(mode=0o700)
        require(not self.paths.state.is_symlink(), 'STATE_SYMLINK')
        atomic_write(self.paths.state / 'state.json', json.dumps(state))

    def read_state(self):
        return json.loads(secure_file(self.paths.state / 'state.json', exact_mode=0o600))

    def context_fingerprint(self):
        # Bind recovery to the original Principal/identities and DB destination.
        # Password rotation alone is not a change of database identity.
        route = make_url(self.env['DATABASE__URL']).set(password=None)
        payload = [asdict(self.plan), route.render_as_string(hide_password=True)]
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def install(self):
        p = self.paths
        gid = pwd.getpwnam('pdi').pw_gid
        p.config.mkdir(mode=0o750)
        os.chown(p.config, 0, gid)
        os.chmod(p.config, 0o750)  # do not inherit an operator's restrictive umask
        (p.config / 'units').mkdir(mode=0o700)
        os.chmod(p.config / 'units', 0o700)
        atomic_write(p.config / 'registry.toml', registry_text(self.plan, self.env), gid=gid, mode=0o640)
        cfg = load_scoped_operator_configuration(p.config / 'registry.toml', environment=self.env)
        require(cfg.router.resolve(self.plan.principal).database_url == self.env['DATABASE__URL'], 'DATABASE_ROUTE')
        for instance in PIPELINES:
            atomic_write(p.config / 'units' / (instance + '.env'), unit_environment(self.plan, self.env, instance))
        atomic_write(p.units / 'pdi-p3c-writer@.service',
                     (self.release / 'deployment/systemd/pdi-p3c-writer@.service').read_text(), mode=0o644)
        for instance in SCHEDULES:
            atomic_write(p.units / f'pdi-p3c-{instance}.timer', timer_text(instance), mode=0o644)
        command(['systemd-analyze', 'verify', str(p.units / 'pdi-p3c-writer@.service'),
                 *(str(p.units / f'pdi-p3c-{i}.timer') for i in SCHEDULES)])
        atomic_symlink(p.current, self.release)
        command(['systemctl', 'daemon-reload'])
        for instance in PIPELINES:
            s = self.properties(f'pdi-p3c-writer@{instance}.service')
            require(s.get('User') == 'pdi' and s.get('Group') == 'pdi' and s.get('NoNewPrivileges') == 'yes'
                    and not s.get('DropInPaths') and s.get('FragmentPath') == str(p.units / 'pdi-p3c-writer@.service'), 'SYSTEMD_OVERRIDE')

    def qualify(self, instance):
        unit = f'pdi-p3c-writer@{instance}.service'
        command(['systemctl', 'start', unit], timeout=21600)
        s = self.properties(unit)
        require(s.get('Result') == 'success' and s.get('ExecMainStatus') == '0' and s.get('ActiveState') == 'inactive', 'SYSTEMD_QUALIFICATION_FAILED')

    def schedules(self, enabled):
        for instance in SCHEDULES:
            command(['systemctl', 'enable' if enabled else 'disable', '--now', f'pdi-p3c-{instance}.timer'])

    def stop(self):
        # Stop services BEFORE waiting for their global lock, otherwise cleanup
        # itself can deadlock against an in-flight or timed-out qualification.
        failures = []
        for unit in [*(f'pdi-p3c-{i}.timer' for i in SCHEDULES), *(f'pdi-p3c-writer@{i}.service' for i in PIPELINES)]:
            try:
                if self.properties(unit).get('LoadState') != 'not-found':
                    actions = [['systemctl', 'stop', unit]]
                    if unit.endswith('.timer'):
                        actions.append(['systemctl', 'disable', unit])
                    for action in actions:
                        try:
                            command(action, timeout=120)
                        except Exception:
                            failures.append(unit)
                    s = self.quiet(unit)
                    if unit.endswith('.timer'):
                        require(s.get('UnitFileState') == 'disabled', 'ABORT_TIMER_STILL_ENABLED')
            except Exception:
                failures.append(unit)
        require(not failures, 'ABORT_STOP_FAILED')

    def verify_files(self):
        p = self.paths
        require(command(['git', '-C', str(self.release), 'rev-parse', 'HEAD']) == self.sha, 'RELEASE_SHA')
        require(command(['git', '-C', str(self.release), 'status', '--porcelain', '--untracked-files=all']) == '', 'RELEASE_DIRTY')
        require(p.current.resolve() == self.release, 'CURRENT_RELEASE_CHANGED')
        gid = pwd.getpwnam('pdi').pw_gid
        for path, mode, group in [(p.config, 0o750, gid), (p.config / 'registry.toml', 0o640, gid),
                                  (p.config / 'units', 0o700, 0)]:
            s = path.lstat()
            require(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and s.st_gid == group and stat.S_IMODE(s.st_mode) == mode, 'INSTALLED_PERMISSIONS')
        require(secure_file(p.config / 'registry.toml') == registry_text(self.plan, self.env), 'REGISTRY_DRIFT')
        for i in PIPELINES:
            require(secure_file(p.config / 'units' / (i + '.env'), exact_mode=0o600) == unit_environment(self.plan, self.env, i), 'UNIT_ENV_DRIFT')
        for i in SCHEDULES:
            require((p.units / f'pdi-p3c-{i}.timer').read_text() == timer_text(i), 'TIMER_DRIFT')
        require((p.units / 'pdi-p3c-writer@.service').read_text() ==
                (self.release / 'deployment/systemd/pdi-p3c-writer@.service').read_text(), 'UNIT_DRIFT')
        for i in PIPELINES:
            s = self.properties(f'pdi-p3c-writer@{i}.service')
            require(s.get('User') == 'pdi' and s.get('Group') == 'pdi' and s.get('NoNewPrivileges') == 'yes'
                    and not s.get('DropInPaths'), 'SYSTEMD_OVERRIDE')

    def verify_schedules(self):
        for i in SCHEDULES:
            s = self.properties(f'pdi-p3c-{i}.timer')
            require(s.get('UnitFileState') == 'enabled' and s.get('ActiveState') == 'active' and not s.get('DropInPaths')
                    and s.get('FragmentPath') == str(self.paths.units / f'pdi-p3c-{i}.timer'), 'SCHEDULE_NOT_ACTIVE')

    def verify_schedules_off(self):
        for i in SCHEDULES:
            s = self.properties(f'pdi-p3c-{i}.timer')
            require(s.get('UnitFileState') == 'disabled' and s.get('ActiveState') == 'inactive', 'PREMATURE_SCHEDULE')


class Cutover:
    """Injectable state machine; production and rehearsal use the same algorithm."""
    def __init__(self, host, expected_counts):
        self.host, self.counts = host, expected_counts
        self.abort_confirmed = False

    def preflight(self):
        h = self.host
        h.preflight()
        return h.db.evidence(enabled=False, expected_counts=self.counts)

    def apply(self):
        h = self.host
        self.abort_confirmed = False
        with h.control():
            state = None
            try:
                with h.sync():
                    before = self.preflight()  # never trust an earlier CLI preflight
                    state = {'phase': 'PREPARED', 'sha': h.sha, 'old_target': os.readlink(h.paths.current),
                             'context': h.context_fingerprint(), 'baseline': before, 'qualified': []}
                    h.save(state)  # durable marker BEFORE any production configuration write
                    h.install()
                    h.verify_files()
                    h.verify_schedules_off()
                    h.db.set_enabled(True)
                    h.db.compare(before, h.db.evidence(enabled=True))
                for instance in QUALIFICATION:
                    # Entire apply retains the independent control lock. The actual
                    # service, not the parent, owns sync.lock during this operation.
                    h.qualify(instance)
                    with h.sync():
                        h.health()
                        h.verify_schedules_off()
                        after = h.db.evidence(enabled=True)
                        h.db.compare(before, after, PIPELINES[instance])
                        before = after
                        state['qualified'].append(instance)
                        h.save(state)
                with h.sync():
                    h.health()
                    h.verify_files()
                    h.verify_schedules_off()
                    final = h.db.evidence(enabled=True)
                    h.db.compare(state['baseline'], final)
                    state['verified'] = final
                    state['phase'] = 'ACTIVATING'
                    h.save(state)
                    h.schedules(True)
                    h.verify_schedules()
                    state['phase'] = 'PASS'
                    h.save(state)
                return 'PASS'
            except BaseException:
                if state is not None:
                    self.abort(state)
                raise

    def abort(self, state):
        h = self.host
        self.abort_confirmed = False
        problems = []
        state['phase'] = 'ABORTING'
        try:
            h.save(state)
        except BaseException:
            problems.append('journal')
        try:
            h.stop()
        except BaseException:
            problems.append('stop')
        try:
            with h.sync():
                require(state.get('context') == h.context_fingerprint(), 'ABORT_CONTEXT_CHANGED')
                h.db.set_enabled(False)
                h.db.verify_disabled()
                h.health()
                # Keep the new release/config inert for diagnosis. Restoring the
                # old release could reactivate legacy composition; no auto rollback.
        except BaseException:
            problems.append('identity')
        state['phase'] = 'ABORT_INCOMPLETE' if problems else 'ABORTED'
        h.save(state)
        require(not problems, 'ABORT_INCOMPLETE')
        self.abort_confirmed = True

    def verify(self):
        h = self.host
        with h.control(), h.sync():
            state = h.read_state()
            require(state['phase'] == 'PASS' and state['sha'] == h.sha and state['qualified'] == list(QUALIFICATION), 'NO_SUCCESSFUL_CUTOVER')
            require(state.get('context') == h.context_fingerprint(), 'VERIFY_CONTEXT_CHANGED')
            h.health()
            h.verify_files()
            h.verify_schedules()
            h.db.compare(state['verified'], h.db.evidence(enabled=True))


def parser():
    p = argparse.ArgumentParser(description='Explicit P3C operator cutover; never an AI tool.')
    p.add_argument('action', choices=('preflight', 'apply', 'verify', 'abort'))
    p.add_argument('--release', type=Path, required=True)
    p.add_argument('--expected-sha', required=True)
    p.add_argument('--production-host', required=True)
    p.add_argument('--rollback-snapshot', required=True)
    p.add_argument('--rollback-source-sha', required=True)
    p.add_argument('--expected-counts', required=True, help='Approved P3B table=count pairs, comma-separated; no DB URL')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    logging.disable(logging.CRITICAL)
    host = None
    cutover = None
    try:
        require(Path(__file__).resolve().is_relative_to(args.release / 'src'), 'EXECUTE_EXACT_RELEASE')
        require(Path(sys.prefix).absolute() == args.release / '.venv', 'RELEASE_PYTHON')
        counts = dict(item.split('=', 1) for item in args.expected_counts.split(','))
        counts = {k: int(v) for k, v in counts.items()}
        require(set(counts) == set(COUNT_KEYS) and all(v >= 0 for v in counts.values()), 'COUNT_ARGUMENT')
        host = Host(Paths(), args.release, args.expected_sha, args.production_host, args.rollback_snapshot, args.rollback_source_sha)
        host.load()
        cutover = Cutover(host, counts)
        def interrupted(*_):
            raise Refused('INTERRUPTED')
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, interrupted)
        if args.action == 'apply':
            cutover.apply()
        elif args.action == 'preflight':
            with host.control(), host.sync():
                cutover.preflight()
        elif args.action == 'verify':
            cutover.verify()
        else:
            with host.control():
                state = host.read_state()
                require(state['sha'] == host.sha, 'ABORT_RELEASE_MISMATCH')
                cutover.abort(state)
        print('MU13_P3C_STATUS=PASS' if args.action in {'apply', 'verify'} else 'MU13_P3C_STATUS=' + args.action.upper() + '_PASS')
        print('SCOPED_WRITER_PRODUCTION_ENABLED=' + ('YES' if args.action in {'apply', 'verify'} else 'NO'))
        print('MULTI_USER_CONSUMER_ENABLED=NO\nLEGACY_WRITERS_DISABLED=YES\nGMAIL_SCOPED_INGESTION=DISABLED\nINTEGRATION_TEST_WRITER=DISABLED\nSCOPED_ENRICHMENT_SCHEDULING=DEFERRED_TO_P3D')
        return 0
    except BaseException as error:
        code = str(error) if isinstance(error, Refused) else 'OPERATION_FAILED'
        print('MU13_P3C_STATUS=FAIL\nERROR_CODE=' + code)
        # Historical journal status cannot establish current cleanup success.
        paused = cutover is not None and cutover.abort_confirmed
        print('SCOPED_WRITER_PRODUCTION_ENABLED=' + ('NO' if paused else 'NOT_CONFIRMED'))
        print('INGESTION_PAUSED=' + ('YES' if paused else 'NOT_CONFIRMED'))
        print('AUTOMATIC_LEGACY_FALLBACK=NO\nAUTOMATIC_DATABASE_ROLLBACK=NO')
        return 1
    finally:
        if host is not None and host.db is not None:
            host.db.engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
