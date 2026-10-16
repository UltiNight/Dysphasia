# Run via `ida.exe -A -S"scripts/ida-start-mcp.py" <target>`.
# Diagnostic variant: logs what plugin names IDA actually has registered, and tries a
# direct module import of mcp-plugin.py as a fallback if load_and_run_plugin("MCP", 0)
# doesn't find it by that name.
import traceback

LOG = r"C:\HFF\MDI\Dysphasia\logs\ida-start-mcp.log"


def log(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


try:
    log("script started")
    import ida_auto
    ida_auto.auto_wait()
    log("auto_wait done")
    import idaapi

    for candidate in ["MCP", "mcp-plugin", "mcp_plugin", "mcp"]:
        try:
            ok = idaapi.load_and_run_plugin(candidate, 0)
            log(f"load_and_run_plugin({candidate!r}) -> {ok!r}")
        except Exception:
            log(f"load_and_run_plugin({candidate!r}) raised:\n" + traceback.format_exc())

    # Fallback: import the plugin file directly and call its entry point ourselves.
    try:
        import importlib.util
        plugin_path = r"C:\Users\LUNES\AppData\Roaming\Hex-Rays\IDA Pro\plugins\mcp-plugin.py"
        spec = importlib.util.spec_from_file_location("dysphasia_mcp_plugin", plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        log("direct import of mcp-plugin.py succeeded")
        plugin_instance = module.PLUGIN_ENTRY()
        plugin_instance.init()
        plugin_instance.run(0)
        log("direct plugin_instance.init()+run(0) completed without exception")
    except Exception:
        log("direct import/run FAILED:\n" + traceback.format_exc())

except Exception:
    log("EXCEPTION:\n" + traceback.format_exc())
