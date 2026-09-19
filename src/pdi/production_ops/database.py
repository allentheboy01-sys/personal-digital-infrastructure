"""Read-only evidence and narrowly scoped identity enable/disable transactions."""

from sqlalchemy import text

from .contracts import COUNT_TABLES, HEAD, MECHANISMS, PROVIDERS, require


class Database:
    def __init__(self, engine, plan, native_ids):
        self.engine, self.plan, self.native_ids = engine, plan, native_ids

    def evidence(self, *, enabled, expected_counts=None):
        p = self.plan
        with self.engine.connect() as c, c.begin():
            c.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            require(c.execute(text("SELECT version_num FROM alembic_version")).scalars().all() == [HEAD], "ALEMBIC_MISMATCH")
            require(c.scalar(text("SHOW server_version_num"))[:2] == "16", "POSTGRES_VERSION")
            def rows(sql, params=None):
                return [dict(r) for r in c.execute(text(sql), params or {}).mappings()]
            instances = rows("SELECT id, provider_type, enabled FROM provider_instances")
            accounts = rows("SELECT id, provider_instance_id, provider_native_id, enabled FROM provider_accounts")
            scopes = rows("SELECT id, provider_instance_id, provider_account_id, enabled FROM observation_scopes")
            require(len(instances) == 4 and len(accounts) == 2 and len(scopes) == 4, "IDENTITY_COUNTS")
            for provider in PROVIDERS:
                active = enabled and provider in MECHANISMS
                i = next((r for r in instances if str(r['id']) == p.instances[provider]), None)
                s = next((r for r in scopes if str(r['id']) == p.scopes[provider]), None)
                require(i is not None and i['provider_type'] == provider and i['enabled'] == active, "INSTANCE_MISMATCH")
                require(s is not None and str(s['provider_instance_id']) == p.instances[provider] and s['enabled'] == active, "SCOPE_MISMATCH")
                if provider in MECHANISMS:
                    a = next((r for r in accounts if str(r['id']) == p.accounts[provider]), None)
                    require(a is not None and str(a['provider_instance_id']) == p.instances[provider] and
                            a['enabled'] == active and a['provider_native_id'] == self.native_ids[provider], "ACCOUNT_MISMATCH")
                    require(str(s['provider_account_id']) == p.accounts[provider], "SCOPE_ACCOUNT_MISMATCH")
                else:
                    require(s['provider_account_id'] is None, "PRESERVATION_ACCOUNT")
            counts = {t: c.scalar(text(f"SELECT count(*) FROM {t}")) for t in COUNT_TABLES}
            counts.update({"sources." + p: c.scalar(text("SELECT count(*) FROM asset_sources WHERE provider = :provider"),
                                                   {"provider": p}) for p in PROVIDERS})
            if expected_counts is not None:
                require(counts == expected_counts, "P3B_COUNTS_MISMATCH")
            require(c.scalar(text("SELECT count(*) FROM asset_sources WHERE observation_scope_id IS NULL")) == 0, "NULL_SOURCE_SCOPE")
            require(c.scalar(text("SELECT count(*) FROM (SELECT 1 FROM asset_sources GROUP BY observation_scope_id, external_id HAVING count(*)>1) q")) == 0, "DUPLICATE_SOURCE")
            for provider in PROVIDERS:
                require(c.scalar(text("SELECT count(*) FROM asset_sources WHERE provider=:p AND observation_scope_id<>CAST(:s AS uuid)"),
                                 {"p": provider, "s": p.scopes[provider]}) == 0, "SOURCE_WRONG_SCOPE")
            require(c.scalar(text("SELECT count(*) FROM asset_sources WHERE provider NOT IN ('nextcloud','immich','gmail','integration-test')")) == 0, "UNEXPECTED_PROVIDER")
            require(c.scalar(text("""SELECT count(*) FROM observation_scope_resource_person_relations r
                WHERE NOT EXISTS (SELECT 1 FROM asset_sources s JOIN blobs b ON b.id=s.blob_id
                  WHERE b.asset_id=r.resource_id AND s.observation_scope_id=r.observation_scope_id)""")) == 0, "RELATION_RESOURCE_EVIDENCE")
            require(c.scalar(text("""SELECT count(*) FROM observation_scope_resource_person_relations r
                WHERE NOT EXISTS (SELECT 1 FROM observation_scope_person_sources s
                  WHERE s.person_id=r.person_id AND s.observation_scope_id=r.observation_scope_id)""")) == 0, "RELATION_PERSON_EVIDENCE")
            for table in ("observation_scope_person_sources", "observation_scope_resource_person_relations"):
                require(c.scalar(text(f"SELECT count(*) FROM {table} WHERE observation_scope_id<>CAST(:s AS uuid)"),
                                 {"s": p.scopes['immich']}) == 0, "DERIVED_WRONG_SCOPE")
            if expected_counts is not None:
                # Full equality including inactive state, labels and original identities.
                for legacy, scoped, columns in (
                    ("person_sources", "observation_scope_person_sources", "external_id,person_id,display_name,inactive_at"),
                    ("resource_person_relations", "observation_scope_resource_person_relations", "resource_id,person_id,inactive_at"),
                ):
                    require(c.scalar(text(f"SELECT count(*) FROM {legacy} WHERE provider<>'immich'")) == 0, "LEGACY_DERIVED_PROVIDER")
                    query = f"""SELECT count(*) FROM (
                      (SELECT {columns} FROM {legacy} EXCEPT SELECT {columns} FROM {scoped})
                      UNION ALL (SELECT {columns} FROM {scoped} EXCEPT SELECT {columns} FROM {legacy})) q"""
                    require(c.scalar(text(query)) == 0, "P3B_DERIVED_NOT_EQUIVALENT")
            states = rows("SELECT observation_scope_id, mechanism, version, reconciliation_required, checkpoint IS NOT NULL AS initialized FROM observation_scope_sync_state")
            require(len(states) == 2, "SCOPED_STATE_COUNT")
            for provider, mechanism in MECHANISMS.items():
                s = next((r for r in states if str(r['observation_scope_id']) == p.scopes[provider] and r['mechanism'] == mechanism), None)
                require(s is not None and s['initialized'] and not s['reconciliation_required'], "STATE_NOT_READY")
                if expected_counts is not None:
                    require(c.scalar(text("""SELECT count(*) FROM provider_sync_state l
                      JOIN observation_scope_sync_state s ON s.observation_scope_id=CAST(:s AS uuid) AND s.mechanism=l.mechanism
                      WHERE l.provider=:p AND l.mechanism=:m AND l.checkpoint IS NOT DISTINCT FROM s.checkpoint
                      AND l.version=s.version AND l.reconciliation_required=s.reconciliation_required"""),
                      {"s": p.scopes[provider], "p": provider, "m": mechanism}) == 1, "STATE_COPY_MISMATCH")
            # Fingerprints remain in a root-only journal, never reports. No personal
            # values/checkpoints are returned to the operator or embedded in errors.
            frozen = {}
            for table in ("person_sources", "resource_person_relations", "provider_sync_state"):
                frozen[table] = c.scalar(text(f"SELECT md5(coalesce(string_agg(h, ',' ORDER BY h), '')) FROM (SELECT md5(row_to_json(t)::text) h FROM {table} t) q"))
            frozen['preserved_sources'] = c.scalar(text("SELECT md5(coalesce(string_agg(h, ',' ORDER BY h), '')) FROM (SELECT md5(row_to_json(t)::text) h FROM asset_sources t WHERE provider IN ('gmail','integration-test')) q"))
            source_ids = c.execute(text("SELECT id::text || ':' || observation_scope_id::text FROM asset_sources ORDER BY id")).scalars().all()
            ledger = rows("SELECT id, pipeline_key, status FROM pipeline_runs")
            require(not any(r['status'] == 'running' for r in ledger), "RUNNING_LEDGER")
            return {"frozen": frozen, "source_ids": source_ids, "counts": counts,
                    "states": {str(r['observation_scope_id']): r['version'] for r in states},
                    "ledger": {str(r['id']): [r['pipeline_key'], r['status']] for r in ledger}}

    @staticmethod
    def compare(before, after, pipeline=None):
        require(before['frozen'] == after['frozen'], "LEGACY_OR_PRESERVATION_MUTATED")
        require(all(before['counts'][k] == after['counts'][k] for k in
                    ('person_sources', 'resource_person_relations', 'provider_sync_state',
                     'resource_statements', 'resource_enrichments')), 'OUT_OF_SCOPE_WRITER')
        require(set(before['source_ids']) <= set(after['source_ids']), "SOURCE_IDENTITY_CHANGED")
        require(set(before['ledger']) <= set(after['ledger']), "LEDGER_REMOVED")
        require(all(after['states'].get(k, -1) >= v for k, v in before['states'].items()), "STATE_REGRESSION")
        if pipeline:
            added = [v for k, v in after['ledger'].items() if k not in before['ledger']]
            require(added == [[pipeline, 'completed']], "QUALIFICATION_LEDGER")

    def set_enabled(self, enabled):
        # One transaction; no insert, migration, provenance transition or state copy.
        order = ("provider_instances", "provider_accounts", "observation_scopes")
        maps = dict(zip(order, (self.plan.instances, self.plan.accounts, self.plan.scopes)))
        with self.engine.begin() as c:
            for table in order if enabled else reversed(order):
                for provider in MECHANISMS:
                    result = c.execute(text(f"UPDATE {table} SET enabled=:e, updated_at=now() WHERE id=CAST(:id AS uuid)"),
                                       {"e": enabled, "id": maps[table][provider]})
                    require(result.rowcount == 1, "ENABLEMENT_TARGET_MISSING")

    def verify_disabled(self):
        """Fresh readback after abort; failed checkpoints/ledgers are allowed.

        UPDATE rowcounts alone do not prove effective disablement or that the
        preservation Providers remained disabled.
        """
        with self.engine.connect() as c, c.begin():
            c.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
            require(c.execute(text("SELECT version_num FROM alembic_version")).scalars().all() == [HEAD], 'ABORT_SCHEMA_MISMATCH')
            for table, expected in (
                ('provider_instances', self.plan.instances),
                ('provider_accounts', self.plan.accounts),
                ('observation_scopes', self.plan.scopes),
            ):
                rows = c.execute(text(f'SELECT id, enabled FROM {table}')).mappings()
                rows = list(rows)
                require({str(r['id']) for r in rows} == set(expected.values()) and
                        all(r['enabled'] is False for r in rows), 'ABORT_IDENTITIES_NOT_DISABLED')
