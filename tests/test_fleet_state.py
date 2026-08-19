"""
Fleet ledger & host-facts tests.

The ledger decides who may execute code here, so it must fail *closed*: a
corrupt blob yields no grants rather than forged ones, unknown capability names
never become grants, and no peer can grow it without bound. Host facts must
never raise — a machine that cannot describe itself still has to stay manageable.
"""
import json
import os
import time

import pytest

from src.apps import fleet_host
from src.apps.fleet_state import (
    CAPABILITIES, MAX_OPERATORS, MAX_PENDING, MAX_PROVISION_RECORDS,
    FleetState, clean_caps, clean_label,
)

PUB = b"\x11" * 64
A = "aa" * 20
B = "bb" * 20


class MemoryStore:
    """Stands in for the node's encrypted drawer."""

    def __init__(self, initial=None):
        self.data = dict(initial or {})

    def get(self, key):
        return self.data.get(key)

    def put(self, key, value):
        self.data[key] = value
        return True

    def delete(self, key):
        return self.data.pop(key, None) is not None


class TestCapabilities:
    def test_unknown_names_are_dropped(self):
        assert clean_caps(["status", "shell", "root", "shell::", ""]) == [
            "status", "shell"]

    def test_non_lists_are_empty(self):
        for junk in (None, "status", 42, {"status": True}):
            assert clean_caps(junk) == []

    def test_order_is_canonical(self):
        """Normalised order, so a stored grant never depends on request order."""
        assert clean_caps(["shell", "status"]) == clean_caps(["status", "shell"])

    def test_labels_are_bounded(self):
        assert len(clean_label("x" * 5000)) == 128
        assert clean_label(None) == ""


class TestOperators:
    def test_grant_and_gate(self):
        state = FleetState()
        assert state.add_operator(A, PUB, caps=["status"]) is not None
        assert state.allows(A, "status") is True
        assert state.allows(A, "shell") is False
        assert state.allows(B, "status") is False

    def test_grant_without_caps_is_refused(self):
        state = FleetState()
        assert state.add_operator(A, PUB, caps=[]) is None
        assert state.add_operator(A, PUB, caps=["nonsense"]) is None
        assert state.allows(A, "status") is False

    def test_grant_needs_a_real_node_id(self):
        state = FleetState()
        for bad in ("", "zz", "aa" * 19, "aa" * 21, "zz" * 20, None, 5):
            assert state.add_operator(bad, PUB, caps=["status"]) is None

    def test_grant_needs_a_key(self):
        state = FleetState()
        assert state.add_operator(A, b"", caps=["status"]) is None

    def test_remove_revokes(self):
        state = FleetState()
        state.add_operator(A, PUB, caps=list(CAPABILITIES))
        assert state.remove_operator(A) is True
        assert state.allows(A, "shell") is False
        assert state.remove_operator(A) is False

    def test_operator_table_is_bounded(self):
        state = FleetState()
        for i in range(MAX_OPERATORS + 20):
            state.add_operator(f"{i:040x}", PUB, caps=["status"])
        assert len(state.operators()) <= MAX_OPERATORS

    def test_proof_is_kept_for_audit(self):
        state = FleetState()
        state.add_operator(A, PUB, caps=["status"], proof=b"signed-blob")
        assert state.operators()[0]["proof"]


class TestPending:
    def test_pending_is_not_a_grant(self):
        state = FleetState()
        state.add_pending_in(A, PUB, caps=["shell"], label="x", proof=b"p")
        assert state.allows(A, "shell") is False
        assert len(state.pending_in()) == 1

    def test_pending_queue_is_bounded(self):
        state = FleetState()
        for i in range(MAX_PENDING + 50):
            state.add_pending_in(f"{i:040x}", PUB, caps=["status"], label="",
                                 proof=b"")
        assert len(state.pending_in()) <= MAX_PENDING

    def test_repeat_request_refreshes_rather_than_stacks(self):
        state = FleetState()
        for _ in range(10):
            state.add_pending_in(A, PUB, caps=["status"], label="", proof=b"")
        assert len(state.pending_in()) == 1

    def test_take_consumes(self):
        state = FleetState()
        state.add_pending_in(A, PUB, caps=["status"], label="", proof=b"")
        assert state.take_pending_in(A) is not None
        assert state.take_pending_in(A) is None

    def test_expired_pending_disappears(self, monkeypatch):
        state = FleetState()
        state.add_pending_in(A, PUB, caps=["status"], label="", proof=b"")
        import src.apps.fleet_state as module
        later = time.time() + module.PENDING_TTL * 2
        monkeypatch.setattr(module.time, "time", lambda: later)
        assert state.pending_in() == []


class TestProvisionRecords:
    def test_single_use(self):
        state = FleetState()
        state.add_provisioned("d" * 64, host="10.0.0.1", caps=["status"])
        assert state.take_provisioned("d" * 64) is not None
        assert state.take_provisioned("d" * 64) is None

    def test_bounded(self):
        state = FleetState()
        for i in range(MAX_PROVISION_RECORDS + 30):
            state.add_provisioned(f"{i:064x}", host="h", caps=["status"])
        assert len(state.provisioned()) <= MAX_PROVISION_RECORDS


class TestPersistence:
    def test_roundtrip(self):
        store = MemoryStore()
        state = FleetState(store)
        state.add_operator(A, PUB, caps=["status", "update"], label="lab")
        state.add_managed(B, caps=["shell"], label="server")
        again = FleetState(store)
        assert again.allows(A, "update") is True
        assert again.managed_one(B)["caps"] == ["shell"]

    def test_corrupt_blob_yields_no_grants(self):
        """Fail closed: forget who you trusted rather than trust a forged list."""
        for blob in (b"not json", b"[]", b"null", b'{"operators": 5}',
                     b"\xff\xfe\x00", b""):
            state = FleetState(MemoryStore({"fleet-state": blob}))
            assert state.operators() == []
            assert state.allows(A, "status") is False

    def test_persisted_unknown_capabilities_are_dropped(self):
        """A tampered file cannot smuggle a capability past the loader."""
        blob = json.dumps({"operators": {A: {"pub": PUB.hex(),
                                             "caps": ["status", "root"]}}})
        state = FleetState(MemoryStore({"fleet-state": blob.encode()}))
        assert state.allows(A, "status") is True
        assert state.allows(A, "root") is False

    def test_one_bad_record_does_not_lose_the_others(self):
        blob = json.dumps({"operators": {A: {"pub": PUB.hex(), "caps": ["status"]},
                                         "bogus": "not a dict"}})
        state = FleetState(MemoryStore({"fleet-state": blob.encode()}))
        assert state.allows(A, "status") is True

    def test_version_moves_on_change(self):
        state = FleetState()
        before = state.version
        state.add_operator(A, PUB, caps=["status"])
        assert state.version > before

    def test_a_full_drawer_does_not_break_a_session(self):
        class FullStore(MemoryStore):
            def put(self, key, value):
                return False

        state = FleetState(FullStore())
        assert state.add_operator(A, PUB, caps=["status"]) is not None
        assert state.allows(A, "status") is True     # in memory regardless


# ---------------------------------------------------------------------------
# Host facts
# ---------------------------------------------------------------------------

class TestHostFacts:
    def test_detect_never_raises(self):
        facts = fleet_host.detect()
        assert facts.detected_at > 0
        assert isinstance(facts.as_dict(), dict)

    def test_status_shape(self):
        status = fleet_host.collect_status(fleet_host.detect())
        for key in ("at", "uptime", "cpu_count", "memory", "disks"):
            assert key in status
        assert isinstance(status["disks"], list)
        for disk in status["disks"]:
            assert disk["total"] > 0 and disk["free"] >= 0

    def test_disks_are_bounded(self):
        assert len(fleet_host.collect_status()["disks"]) <= fleet_host._MAX_DISKS

    def test_os_release_parsing_is_bounded(self, tmp_path):
        path = tmp_path / "os-release"
        path.write_text('ID="debian"\nPRETTY_NAME="Debian GNU/Linux"\n'
                        + "JUNK=" + "x" * 5000 + "\n"
                        + "\n".join(f"K{i}=v" for i in range(500)))
        parsed = fleet_host.read_os_release(str(path))
        assert parsed["ID"] == "debian"
        assert len(parsed) <= 64
        assert all(len(v) <= fleet_host._MAX_FIELD for v in parsed.values())

    def test_os_release_missing_is_empty(self):
        assert fleet_host.read_os_release("/nonexistent/os-release") == {}

    def test_update_argv_is_argv_never_a_shell_string(self):
        facts = fleet_host.detect()
        commands = fleet_host.update_argv(facts)
        if commands is None:
            pytest.skip("no package manager on this host")
        for command in commands:
            assert isinstance(command, list)
            assert all(isinstance(part, str) for part in command)

    def test_no_package_manager_means_no_update(self):
        facts = fleet_host.HostFacts(package_manager=None, escalation=None)
        assert facts.can_update is False
        assert fleet_host.update_argv(facts) is None

    def test_no_path_to_root_means_no_update(self):
        facts = fleet_host.HostFacts(package_manager="apt", escalation="none",
                                     plan={"refresh": ["apt-get", "update"]})
        assert facts.can_update is False
        assert fleet_host.update_argv(facts) is None

    def test_escalation_is_prefixed(self):
        facts = fleet_host.HostFacts(
            package_manager="apt", escalation="sudo",
            plan={"refresh": ["apt-get", "update"],
                  "upgrade": ["apt-get", "-y", "dist-upgrade"]})
        commands = fleet_host.update_argv(facts)
        assert commands[0][:2] == ["sudo", "-n"]     # never an interactive prompt
        assert commands[1][2] == "apt-get"

    def test_root_needs_no_prefix(self):
        facts = fleet_host.HostFacts(
            package_manager="apk", escalation=None,
            plan={"refresh": ["apk", "update"], "upgrade": ["apk", "upgrade"]})
        assert fleet_host.update_argv(facts) == [["apk", "update"],
                                                 ["apk", "upgrade"]]
