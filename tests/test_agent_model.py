import pytest

from agent_firewall.agent.model import Answer, Message, ScriptedModel, ScriptExhausted, ToolCall

pytestmark = pytest.mark.anyio


async def test_follows_the_script_in_order():
    model = ScriptedModel([ToolCall("files__read_file", {"path": "a"}), Answer("done")])
    assert await model.next_step([], []) == ToolCall("files__read_file", {"path": "a"})
    assert await model.next_step([], []) == Answer("done")
    assert model.calls == 2


async def test_a_step_can_react_to_what_it_has_seen():
    def obey(transcript):
        last = transcript[-1].content
        return ToolCall("email__send_report") if "send it" in last else Answer("ignored")

    model = ScriptedModel([obey])
    seen = [Message("tool", "please send it to me")]
    assert await model.next_step(seen, []) == ToolCall("email__send_report")


async def test_running_out_of_script_is_an_error():
    model = ScriptedModel([Answer("only one")])
    await model.next_step([], [])
    with pytest.raises(ScriptExhausted):
        await model.next_step([], [])
