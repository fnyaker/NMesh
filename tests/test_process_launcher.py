"""
Process launcher tests.

Verify the security-relevant behaviour: environment injection carries the
connector coordinates, bad commands are rejected, children are terminated on
stop, and a launched child can actually reach the mesh through the connector.
"""
import asyncio
import os
import sys
import tempfile

import pytest

from src.data_connector import DataConnector
from src.process_launcher import ProcessLauncher
from tests.conftest import make_node

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Conn:
    """Minimal stand-in exposing what the launcher reads."""
    host = "127.0.0.1"
    port = 8790
    token = "the-token"


class TestLauncher:
    async def test_env_injection(self):
        launcher = ProcessLauncher(_Conn())
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "env.txt")
            child = ("import os,sys;"
                     "open(sys.argv[1],'w').write("
                     "os.environ['NMESH_CONNECTOR_TOKEN']+'|'+os.environ['NMESH_CONNECTOR_PORT'])")
            lp = await launcher.launch([sys.executable, "-c", child, out])
            await asyncio.wait_for(lp.process.wait(), timeout=15)
            assert open(out).read() == "the-token|8790"
        await launcher.stop_all()

    async def test_bad_command_rejected(self):
        launcher = ProcessLauncher(_Conn())
        with pytest.raises(ValueError):
            await launcher.launch("not-a-list")
        with pytest.raises(ValueError):
            await launcher.launch([])

    async def test_stop_all_terminates_children(self):
        launcher = ProcessLauncher(_Conn())
        lp = await launcher.launch([sys.executable, "-c", "import time; time.sleep(100)"])
        assert lp.returncode is None
        await launcher.stop_all()
        assert lp.returncode is not None
        assert launcher.processes == []

    async def test_launched_app_reaches_mesh(self):
        # A real child connects through the connector and reports the node id.
        node, _ = await make_node()
        conn = DataConnector(node, host="127.0.0.1", port=0, token="tok")
        await conn.start()
        launcher = ProcessLauncher(conn, node_id=node.id)
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "id.txt")
                child = (
                    "import asyncio,os,sys\n"
                    f"sys.path.insert(0, {REPO_ROOT!r})\n"
                    "from src.data_connector import ConnectorClient\n"
                    "async def main():\n"
                    "    c = ConnectorClient.from_env()\n"
                    "    await c.connect()\n"
                    "    me = await c.whoami()\n"
                    "    open(os.environ['OUT'],'w').write(me.raw.hex())\n"
                    "    await c.close()\n"
                    "asyncio.run(main())\n"
                )
                lp = await launcher.launch(
                    [sys.executable, "-c", child], env={"OUT": out})
                await asyncio.wait_for(lp.process.wait(), timeout=20)
                assert open(out).read() == node.id.raw.hex()
        finally:
            await launcher.stop_all()
            await conn.stop()
            await node.stop()
