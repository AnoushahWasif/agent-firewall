import pytest
from mcp import Client

from agent_firewall.agent.loop import MAX_RESULT_CHARS, run_task
from agent_firewall.agent.model import Answer, ScriptedModel, ToolCall
from agent_firewall.tools.files import build_server

pytestmark = pytest.mark.anyio


@pytest.fixture
def server(tmp_path):
    (tmp_path / "auth.log").write_text("02:11 sshd: Failed password for root\n")
    (tmp_path / "huge.log").write_text("y" * (MAX_RESULT_CHARS * 2))
    return build_server(tmp_path)


async def test_reads_a_log_and_answers(server):
    def summarise(transcript):
        assert "Failed password" in transcript[-1].content
        return Answer("One failed root login at 02:11.")

    model = ScriptedModel([ToolCall("read_file", {"path": "auth.log"}), summarise])
    async with Client(server) as c:
        run = await run_task("What happened last night?", c, model)
    assert run.stopped == "answered" and run.answer == "One failed root login at 02:11."
    assert run.tool_calls == 1
    assert [m.role for m in run.transcript] == ["user", "assistant", "tool", "assistant"]


async def test_tool_errors_go_back_to_the_model(server):
    model = ScriptedModel([ToolCall("read_file", {"path": "../etc/passwd"}), Answer("can't")])
    async with Client(server) as c:
        run = await run_task("read it", c, model)
    tool = run.transcript[2]
    assert tool.is_error and "outside the shared folder" in tool.content


async def test_a_tool_that_was_not_listed_is_never_called(server):
    model = ScriptedModel([ToolCall("delete_everything"), Answer("ok")])
    async with Client(server) as c:
        run = await run_task("x", c, model)
    assert run.transcript[2].is_error and "No tool named" in run.transcript[2].content


async def test_stops_at_the_step_limit(server):
    model = ScriptedModel([ToolCall("list_files")] * 10)
    async with Client(server) as c:
        run = await run_task("loop forever", c, model, max_steps=3)
    assert run.stopped == "step_limit" and run.tool_calls == 3 and run.answer is None


async def test_a_failing_model_ends_the_run(server):
    model = ScriptedModel([])
    async with Client(server) as c:
        run = await run_task("x", c, model)
    assert run.stopped == "model_error" and "ScriptExhausted" in run.transcript[-1].content


async def test_long_results_are_cut_before_the_model_sees_them(server):
    model = ScriptedModel(
        [ToolCall("read_file", {"path": "huge.log", "max_bytes": 100_000}), Answer("big")]
    )
    async with Client(server) as c:
        run = await run_task("x", c, model)
    assert len(run.transcript[2].content) < MAX_RESULT_CHARS + 50
    assert run.transcript[2].content.endswith("[cut: result is longer]")
