"""Private Ghidra worker. Its command interface is not exposed to LLMs."""
from __future__ import annotations

import argparse
import json
import os
import resource
import signal
from pathlib import Path


def address(value) -> str:
    return hex(int(value.getOffset()) & ((1 << 64) - 1))


def function_summary(function) -> dict:
    return {
        "address": address(function.getEntryPoint()), "name": str(function.getName()),
        "size": int(function.getBody().getNumAddresses()), "signature": str(function.getSignature()),
        "comment": str(function.getComment()) if function.getComment() is not None else None,
        "decompiled": None, "disassembly": [], "callers": [], "callees": [],
        "detail_loaded": False,
    }


def analyze_program(program, monitor) -> bool:
    """Return actual analysis cancellation before disposing the timeout timer.

    PyGhidra 3.1's convenience analyze() cancels its monitor after success as timer
    cleanup. Reading that monitor afterward cannot distinguish success/timeout.
    """
    import pyghidra
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.util import GhidraProgramUtilities

    with pyghidra.transaction(program, "Ghidrama analysis"):
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            manager = AutoAnalysisManager.getAnalysisManager(program)
            manager.initializeOptions()
            manager.reAnalyzeAll(None)
            try:
                manager.startAnalysis(monitor, True)
            except Exception:
                if not monitor.isCancelled():
                    raise
            cancelled = bool(monitor.isCancelled())
            if not cancelled:
                GhidraProgramUtilities.markProgramAnalyzed(program)
            return cancelled
        finally:
            monitor.cancel()
            GhidraScriptUtil.releaseBundleHostReference()


def function_detail(program, function, monitor) -> dict:
    from ghidra.app.decompiler import DecompInterface

    result = function_summary(function)
    interface = DecompInterface()
    try:
        interface.openProgram(program)
        decompiled = interface.decompileFunction(function, 30, monitor)
        if decompiled.decompileCompleted():
            code = str(decompiled.getDecompiledFunction().getC())
            result["decompiled"] = code[:1_000_000]
            result["decompiled_truncated"] = len(code) > 1_000_000
        else:
            result["decompile_error"] = str(decompiled.getErrorMessage()) or "The decompiler could not recover this function."
    finally:
        interface.dispose()
    for index, instruction in enumerate(program.getListing().getInstructions(function.getBody(), True)):
        if index >= 5000:
            result["disassembly_truncated"] = True
            break
        result["disassembly"].append({"address": address(instruction.getAddress()), "bytes": " ".join(f"{int(b) & 255:02x}" for b in instruction.getBytes()), "mnemonic": str(instruction.getMnemonicString()), "operands": ", ".join(str(instruction.getDefaultOperandRepresentation(i)) for i in range(instruction.getNumOperands()))})
    for key, functions in [("callers", function.getCallingFunctions(monitor)), ("callees", function.getCalledFunctions(monitor))]:
        result[key] = [{"address": address(f.getEntryPoint()), "address_space": str(f.getEntryPoint().getAddressSpace().getName()), "name": str(f.getName())} for f in functions][:1000]
    result["detail_loaded"] = True
    return result


def export_program(program, monitor, original: Path, warnings=None) -> dict:
    from ghidra.framework import Application
    import pefile

    result = {"image_base": address(program.getImageBase()), "entry_point": address(program.getImageBase()), "architecture": str(program.getLanguageID()), "format": str(program.getExecutableFormat()), "functions": [], "imports": [], "exports": [], "strings": [], "sections": [], "engine": {"name": "Ghidra", "version": str(Application.getApplicationVersion())}, "warnings": warnings or [], "partial": bool(warnings)}
    for index, function in enumerate(program.getFunctionManager().getFunctions(True)):
        if index >= 10000:
            result["warnings"].append("Function index capped at 10,000 entries.")
            result["partial"] = True
            break
        result["functions"].append(function_summary(function))
    # PE tables distinguish the executable entry point from actual exports and give
    # useful import address-table VAs instead of Ghidra's synthetic EXTERNAL offsets.
    with pefile.PE(str(original), fast_load=True) as pe:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"], pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        result["entry_point"] = hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        for module in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            library = module.dll.decode("utf-8", errors="replace")
            for imported in module.imports:
                if len(result["imports"]) >= 10000:
                    break
                result["imports"].append({"address": hex(imported.address), "address_space": "ram", "name": imported.name.decode("utf-8", errors="replace") if imported.name else f"ordinal_{imported.ordinal}", "library": library})
        export_table = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        for exported in list(export_table.symbols if export_table else [])[:10000]:
            result["exports"].append({"address": hex(pe.OPTIONAL_HEADER.ImageBase + exported.address), "name": exported.name.decode("utf-8", errors="replace") if exported.name else f"ordinal_{exported.ordinal}", "ordinal": exported.ordinal, "forwarder": exported.forwarder.decode("utf-8", errors="replace") if exported.forwarder else None})
    for data in program.getListing().getDefinedData(True):
        if len(result["strings"]) >= 10000:
            result["warnings"].append("String index capped at 10,000 entries.")
            break
        if data.hasStringValue():
            result["strings"].append({"address": address(data.getAddress()), "value": str(data.getValue())[:8192]})
    for block in program.getMemory().getBlocks():
        result["sections"].append({"name": str(block.getName()), "address": address(block.getStart()), "size": int(block.getSize()), "permissions": ("r" if block.isRead() else "-") + ("w" if block.isWrite() else "-") + ("x" if block.isExecute() else "-")})
    return result


def execute(args) -> dict:
    import pyghidra

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (args.timeout + 60, args.timeout + 65))
    pyghidra.start(install_dir=Path(os.environ["GHIDRA_INSTALL_DIR"]))
    folder = Path(args.sample_dir)
    import re
    from .unpacking import project_directory
    if args.input_name != "original.bin" and not re.fullmatch(r"unpacked-[0-9a-f]{64}\.bin", args.input_name):
        raise ValueError("Invalid analysis input filename.")
    source = folder / args.input_name
    projects = project_directory(folder, source)
    projects.mkdir(exist_ok=True)
    monitor = pyghidra.task_monitor(args.timeout)
    with pyghidra.open_project(projects, "main", create=True) as project:
        if project.getProjectData().getFile("/program") is None:
            if args.action != "analyze":
                raise ValueError("The Ghidra project has not been imported yet.")
            loader = pyghidra.program_loader().project(project).source(str(source)).name("program")
            with loader.load() as results:
                results.save(monitor)
        with pyghidra.program_context(project, "/program") as program:
            warnings = []
            if args.action == "analyze":
                if analyze_program(program, monitor):
                    warnings.append("Analysis reached its time limit; available results are partial.")
                monitor = pyghidra.task_monitor(60)
                program.save("Ghidrama analysis", monitor)
            if args.action == "functions":
                functions = []
                for target_address in args.addresses or []:
                    target = program.getAddressFactory().getDefaultAddressSpace().getAddress(target_address)
                    function = program.getFunctionManager().getFunctionAt(target)
                    if function is None:
                        raise ValueError("Function not found at the supplied address.")
                    try:
                        functions.append(function_detail(program, function, pyghidra.task_monitor(35)))
                    except Exception:
                        functions.append({**function_summary(function),
                                          "decompile_error": "Ghidra could not recover this function. Inspect its assembly."})
                return {"functions": functions}
            if args.action == "function":
                target = program.getAddressFactory().getDefaultAddressSpace().getAddress(args.address)
                function = program.getFunctionManager().getFunctionAt(target)
                if function is None:
                    raise ValueError("Function not found at the supplied address.")
                return function_detail(program, function, pyghidra.task_monitor(60))
            if args.action == "annotate":
                from ghidra.program.model.symbol import SourceType
                proposal = json.loads(Path(args.proposal).read_text())
                target = program.getAddressFactory().getDefaultAddressSpace().getAddress(proposal["address"])
                function = program.getFunctionManager().getFunctionAt(target)
                if function is None:
                    raise ValueError("The target function no longer exists.")
                with pyghidra.transaction(program, "Ghidrama reviewed annotation"):
                    if proposal["kind"] == "rename":
                        function.setName(proposal["value"], SourceType.USER_DEFINED)
                    elif proposal["kind"] == "comment":
                        function.setComment(proposal["value"])
                    else:
                        raise ValueError("Unsupported annotation kind.")
                program.save("Ghidrama annotation " + proposal["id"], monitor)
            return export_program(program, monitor, source, warnings)


def main():
    # Kill the JVM if its API/MCP parent disappears, including during agent cancellation.
    if os.name == "posix" and Path("/proc/self").exists():
        import ctypes
        expected_parent = int(os.environ.get("GHIDRAMA_PARENT_PID", str(os.getppid())))
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "Could not configure worker parent-death signal")
        if os.getppid() != expected_parent:
            return
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-dir", required=True)
    parser.add_argument("--input-name", default="original.bin")
    parser.add_argument("--action", choices=["analyze", "function", "functions", "annotate"], required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--address")
    parser.add_argument("--addresses", nargs="+", default=[])
    parser.add_argument("--proposal")
    args = parser.parse_args()
    try:
        result = execute(args)
    except Exception as error:
        import traceback
        traceback.print_exc()
        result = {"error": str(error)}
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
