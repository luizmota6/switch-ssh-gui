#!/usr/bin/env python3
import sys, os, tty, termios
paging = True
out = sys.stdout
def w(s): out.write(s); out.flush()
def readline():
    buf = ""
    while True:
        c = os.read(0, 1).decode(errors="ignore")
        if c in ("\r", "\n"): w("\r\n"); return buf
        if c == "\x03": w("^C\r\n"); return ""
        if c in ("\x7f", "\x08"):
            if buf: buf = buf[:-1]; w("\x08 \x08")
            continue
        buf += c; w(c)
def page(lines):
    for i, l in enumerate(lines):
        if paging and i and i % 20 == 0:
            w("-- MORE --, next page: Space, next line: Enter, quit: Control-C")
            c = os.read(0, 1)
            w("\r\x1b[2K")
            if c == b"\x03": return
        w(l + "\r\n")
tty.setraw(0)
w("\x1b[2J\x1b[1;1HAruba AOS-CX (simulado)\r\nPress any key to continue")
os.read(0, 1); w("\r\x1b[2K")
while True:
    w("\x1b[1mSWT-LAB#\x1b[0m ")
    cmd = readline().strip()
    if cmd == "no page": paging = False
    elif cmd == "show version": w("ArubaOS-CX\r\nVersion : FL.10.13.1000\r\nUptime  : 12 days\r\n")
    elif cmd == "show interface brief":
        page([f"1/1/{i:<3} 1   access  up    1000  --" for i in range(1, 49)])
    elif cmd in ("exit", "logout"): w("bye\r\n"); break
    elif cmd: w(f"% Invalid input: {cmd}\r\n")
