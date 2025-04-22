#!/usr/bin/env python3
import sys
from pathlib import Path

import click
import frida

SCRIPT = (Path(__file__).parent / "script.js").read_text()

def spawn_and_hook(program, port=8080, filter_expr="true"):
    """
    Spawn a new process (by path or name) and hook it.
    Behaves exactly as before.
    """
    pid = frida.spawn(program)
    _do_hook(pid, port, filter_expr)
    frida.resume(pid)

def hook(target, port=8080, filter_expr="true"):
    """
    If `target` is all digits, treat as PID and hook that one.
    Otherwise, treat as a process name: enumerate all processes,
    and hook every matching PID.
    """
    # helper to attach one PID
    def _do_hook(pid, port, filter_expr):
        session = frida.attach(pid)
        script_src = SCRIPT.replace("PORT", str(port)).replace("FILTER", filter_expr)
        frida_script = session.create_script(script_src)
        frida_script.load()
        print(f"[+] hooked PID {pid} → localhost:{port}")

    # dispatch based on whether it's a PID or a name
    if isinstance(target, str) and target.isdigit():
        pid = int(target)
        _do_hook(pid, port, filter_expr)
    else:
        # assume process name
        device = frida.get_local_device()
        procs = device.enumerate_processes()
        matched = [p for p in procs if p.name == target]
        if not matched:
            print(f"[!] no running processes named '{target}' found", file=sys.stderr)
            sys.exit(1)
        for p in matched:
            _do_hook(p.pid, port, filter_expr)

@click.command(name="spawn-and-hook",
               help="Spawn a program (path or name), then hook its connect() calls")
@click.argument("program")
@click.option("-p", "--port",     type=int, default=8080, show_default=True,
              help="Local port to redirect to")
@click.option("--filter", "filter_expr", type=str, default="true", show_default=True,
              help="JavaScript filter expression (uses sa_family, addr, port)")
def _main_spawn(program, port, filter_expr):
    spawn_and_hook(program, port, filter_expr)
    if not sys.flags.interactive:
        sys.stdin.read()    # keep alive

@click.command(name="hook",
               help="Attach to existing processes by name or PID")
@click.argument("target")
@click.option("-p", "--port",     type=int, default=8080, show_default=True,
              help="Local port to redirect to")
@click.option("--filter", "filter_expr", type=str, default="true", show_default=True,
              help="JavaScript filter expression (uses sa_family, addr, port)")
def _main_hook(target, port, filter_expr):
    hook(target, port, filter_expr)
    if not sys.flags.interactive:
        sys.stdin.read()    # keep alive

if __name__ == "__main__":
    # if you install via setup.py entry_points, both commands will be available
    # otherwise you can hook one of them here:
    _main_hook()
