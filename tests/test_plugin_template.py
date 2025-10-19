from menuscript.plugins.plugin_template import Plugin

def test_template_plugin_runs(tmp_path):
    p = Plugin()
    prepared = p.prepare("example", ["--opt"], "lab")
    res = p.run(prepared)
    assert res["tool"] == "template"
    assert "log" in res
    assert res["status"] == "done"
