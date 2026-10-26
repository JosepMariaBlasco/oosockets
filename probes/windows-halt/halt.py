# Windows probe: does a real Ctrl-C (CTRL_C_EVENT) reach a Rexx program
# whose activity waits in ooSockets? Each case: a driver in a console of
# its own runs `rexx case.rex` there, waits for "ready", and sends
# CTRL_C_EVENT to the console half a second later (it survives it itself).
# Usage: python halt.py <directory with liboosockets / oosockets.dll and sockets.cls>
import ctypes, os, subprocess, sys, time
from ctypes import wintypes
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
HANDLER = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
me = os.path.abspath(__file__)
here = os.path.dirname(me)

CASES = {
  # the control: no ooSockets, Rexx running clauses
  "sysSleep": 'do 100; call SysSleep 0.05; end',
  "accept": 'srv = .ServerSocket~new(0, "127.0.0.1"); c = srv~accept',
  "receive": 's = .DatagramSocket~new(0, "127.0.0.1"); d = s~receive',
  "lineIn": 'srv = .ServerSocket~new(0, "127.0.0.1"); c = .Socket~new("127.0.0.1", srv~localPort); p = srv~accept; x = c~lineIn',
  "receive, another activity waiting too": 's = .DatagramSocket~new(0, "127.0.0.1"); m = .W~new~start("w", .DatagramSocket~new(0, "127.0.0.1")); d = s~receive',
}
PROG = '''signal on halt
say "ready"
{body}
say "not halted"
exit
halt: say "HALT at line" sigl
exit
::requires "sockets.cls"
::class W
::method w
  use arg s
  signal on halt
  d = s~receive
  return
halt: say "HALT in the other activity too"
'''

role = sys.argv[1] if len(sys.argv) > 1 else "top"

if role != "driver":
    lib = os.path.abspath(sys.argv[1])
    for name, body in CASES.items():
        prog = os.path.join(here, "case.rex")
        open(prog, "w").write(PROG.replace("{body}", body))
        out = os.path.join(here, "out.txt")
        env = dict(os.environ, REXX_PATH=lib, PATH=lib + os.pathsep + os.environ["PATH"])
        with open(out, "w") as f:
            p = subprocess.Popen([sys.executable, me, "driver", prog], stdout=f, stderr=subprocess.STDOUT,
                                 env=env, creationflags=subprocess.CREATE_NEW_CONSOLE)
            try: p.wait(60)
            except subprocess.TimeoutExpired: p.kill(); print("(driver hung)")
        print(f"== {name}:")
        print(open(out).read().rstrip())
    sys.exit(0)

prog = sys.argv[2]
# A process started in a new console may have Ctrl-C disabled, and its
# children inherit that: enable it (for the child), then survive it here.
k32.SetConsoleCtrlHandler(None, False)
keep = HANDLER(lambda t: True)                 # the driver survives the event
k32.SetConsoleCtrlHandler(keep, True)
t0 = time.time()
p = subprocess.Popen(["rexx", prog], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
lines = []
for line in p.stdout:
    lines.append(line.rstrip())
    if line.strip() == "ready": break
time.sleep(0.5)
sent = time.time()
ok = k32.GenerateConsoleCtrlEvent(0, 0)        # CTRL_C_EVENT to the whole console
try: rest, _ = p.communicate(timeout=15)
except subprocess.TimeoutExpired: p.kill(); rest, _ = p.communicate(); lines.append("(hung 15 s, killed)")
lines += [l for l in rest.splitlines() if l]
print(f"   sent={ok} exit {p.returncode:#x}, {time.time() - sent:.2f} s after the event")
for l in lines: print("   ", l)
