import os
import re
import secrets
import sys
import time
from typing import Optional, Tuple
import termios
import tty

from src.constants import A, DEBUG_LOG, LOG_MAX_BYTES

_ansi_re = re.compile(r"\033\[[^m]*m")


def _dbg(msg: str):
    try:
        os.makedirs("results", exist_ok=True)
        if os.path.exists(DEBUG_LOG):
            try:
                sz = os.path.getsize(DEBUG_LOG)
                if sz > LOG_MAX_BYTES:
                    bak = DEBUG_LOG + ".1"
                    if os.path.exists(bak):
                        os.remove(bak)
                    os.rename(DEBUG_LOG, bak)
            except OSError:
                pass
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except OSError:
        pass


def _char_width(c: str) -> int:
    o = ord(c)
    if (
        0x1100 <= o <= 0x115F
        or 0x2329 <= o <= 0x232A
        or 0x2E80 <= o <= 0x303E
        or 0x3040 <= o <= 0x33BF
        or 0x3400 <= o <= 0x4DBF
        or 0x4E00 <= o <= 0xA4CF
        or 0xA960 <= o <= 0xA97C
        or 0xAC00 <= o <= 0xD7A3
        or 0xF900 <= o <= 0xFAFF
        or 0xFE10 <= o <= 0xFE6F
        or 0xFF01 <= o <= 0xFF60
        or 0xFFE0 <= o <= 0xFFE6
        or 0x1F000 <= o <= 0x1FAFF
        or 0x20000 <= o <= 0x2FA1F
        or 0x2600 <= o <= 0x27BF
        or 0x2700 <= o <= 0x27BF
        or 0xFE00 <= o <= 0xFE0F
        or 0x200D == o
        or 0x231A <= o <= 0x231B
        or 0x23E9 <= o <= 0x23F3
        or 0x23F8 <= o <= 0x23FA
        or 0x25AA <= o <= 0x25AB
        or 0x25B6 == o or 0x25C0 == o
        or 0x25FB <= o <= 0x25FE
        or 0x2614 <= o <= 0x2615
        or 0x2648 <= o <= 0x2653
        or 0x267F == o
        or 0x2693 == o
        or 0x26A1 == o
        or 0x26AA <= o <= 0x26AB
        or 0x26BD <= o <= 0x26BE
        or 0x26C4 <= o <= 0x26C5
        or 0x26D4 == o
        or 0x26EA == o
        or 0x26F2 <= o <= 0x26F3
        or 0x26F5 == o
        or 0x26FA == o
        or 0x26FD == o
        or 0x2702 == o
        or 0x2705 == o
        or 0x2708 <= o <= 0x270D
        or 0x270F == o
        or 0x2753 <= o <= 0x2755
        or 0x2757 == o
        or 0x2795 <= o <= 0x2797
        or 0x27B0 == o or 0x27BF == o
    ):
        return 2
    if o in (0xFE0F, 0xFE0E, 0x200D, 0x200B, 0x200C, 0x200E, 0x200F):
        return 0
    return 1


def _vl(s: str) -> int:
    clean = _ansi_re.sub("", s)
    return sum(_char_width(c) for c in clean)


def _w(text: str):
    sys.stdout.write(text)


def _fl():
    sys.stdout.flush()


def enable_ansi():
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            m = ctypes.c_ulong()
            k.GetConsoleMode(h, ctypes.byref(m))
            k.SetConsoleMode(h, m.value | 0x0004)
        except (OSError, AttributeError):
            pass


def term_size() -> Tuple[int, int]:
    try:
        c, r = os.get_terminal_size()
        return max(c, 60), max(r, 20)
    except (ValueError, OSError):
        return 80, 24


def _read_key_blocking() -> str:
    if sys.platform == "win32":
        import msvcrt
        try:
            k = msvcrt.getch()
        except OSError:
            return "esc"
        if k in (b"\x00", b"\xe0"):
            try:
                k2 = msvcrt.getch()
            except OSError:
                return ""
            return {b"H": "up", b"P": "down", b"K": "left", b"M": "right"}.get(k2, "")
        if k == b"\r":
            return "enter"
        if k == b"\x03":
            return "ctrl-c"
        if k == b"\x1b":
            return "esc"
        return k.decode("latin-1", errors="replace")
    else:
        import select as _sel
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                rdy, _, _ = _sel.select([sys.stdin], [], [], 0.2)
                if rdy:
                    ch2 = sys.stdin.read(1)
                    if ch2 == "[":
                        rdy2, _, _ = _sel.select([sys.stdin], [], [], 0.2)
                        if rdy2:
                            ch3 = sys.stdin.read(1)
                            return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(ch3, "esc")
                    return "esc"
                return "esc"
            if ch == "\r" or ch == "\n":
                return "enter"
            if ch == "\x03":
                return "ctrl-c"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _read_key_nb(timeout: float = 0.05) -> Optional[str]:
    if sys.platform == "win32":
        import msvcrt
        try:
            if msvcrt.kbhit():
                return _read_key_blocking()
        except OSError:
            pass
        time.sleep(timeout)
        return None
    else:
        import select
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            rdy, _, _ = select.select([sys.stdin], [], [], timeout)
            if rdy:
                ch = sys.stdin.read(1)
                if ch == "\x1b":
                    rdy2, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if rdy2:
                        ch2 = sys.stdin.read(1)
                        if ch2 == "[":
                            rdy3, _, _ = select.select([sys.stdin], [], [], 0.2)
                            if rdy3:
                                ch3 = sys.stdin.read(1)
                                return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(ch3, "")
                        return ""
                    return "esc"
                if ch in ("\r", "\n"):
                    return "enter"
                if ch == "\x03":
                    return "ctrl-c"
                return ch
            return None
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _wait_any_key():
    if sys.platform == "win32":
        import msvcrt
        try:
            msvcrt.getch()
        except OSError:
            pass
    else:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _prompt_number(prompt: str, max_val: int) -> Optional[int]:
    _w(A.SHOW)
    _w(f"\n {prompt}")
    _fl()
    buf = ""
    if sys.platform == "win32":
        import msvcrt
        while True:
            try:
                k = msvcrt.getch()
            except OSError:
                _w("\n")
                return None
            if k == b"\r":
                break
            if k == b"\x1b" or k == b"\x03":
                _w("\n")
                return None
            if k == b"\x08" and buf:
                buf = buf[:-1]
                _w("\b \b")
                _fl()
                continue
            ch = k.decode("latin-1", errors="replace")
            if ch.isdigit():
                buf += ch
                _w(ch)
                _fl()
    else:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    break
                if ch == "\x1b" or ch == "\x03":
                    _w("\n")
                    return None
                if ch == "\x7f" and buf:
                    buf = buf[:-1]
                    _w("\b \b")
                    _fl()
                    continue
                if ch.isdigit():
                    buf += ch
                    _w(ch)
                    _fl()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    _w(A.HIDE)
    if buf and buf.isdigit():
        n = int(buf)
        if 1 <= n <= max_val:
            return n
    return None


def _flush_stdin():
    if sys.platform == "win32":
        import msvcrt
        time.sleep(0.05)
        try:
            while msvcrt.kbhit():
                msvcrt.getwch()
        except OSError:
            pass
    else:
        import select
        fd = sys.stdin.fileno()
        while select.select([sys.stdin], [], [], 0.0)[0]:
            os.read(fd, 4096)


def _restore_console_input():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-10)
        m = ctypes.c_ulong()
        k.GetConsoleMode(h, ctypes.byref(m))
        need = 0x0007
        if (m.value & need) != need:
            k.SetConsoleMode(h, m.value | need)
    except (OSError, ValueError):
        pass


def _fmt_elapsed(secs: float) -> str:
    m, s = divmod(int(secs), 60)
    if m > 0:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def _ws_frame_encode(data: bytes, opcode: int = 0x02) -> bytes:
    mask = secrets.token_bytes(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    length = len(data)
    if length <= 125:
        header = bytes([0x80 | opcode, 0x80 | length])
    elif length <= 65535:
        header = bytes([0x80 | opcode, 0xFE]) + length.to_bytes(2, 'big')
    else:
        header = bytes([0x80 | opcode, 0xFF]) + length.to_bytes(8, 'big')
    return header + mask + masked


class _WsFrameParser:
    __slots__ = ('_buf',)

    def __init__(self, initial: bytes = b""):
        self._buf = bytearray(initial)

    def feed(self, data: bytes) -> None:
        self._buf.extend(data)

    def next_frame(self) -> Optional[Tuple[int, bytes]]:
        buf = self._buf
        if len(buf) < 2:
            return None
        opcode = buf[0] & 0x0F
        masked = bool(buf[1] & 0x80)
        plen = buf[1] & 0x7F
        off = 2
        if plen == 126:
            if len(buf) < 4:
                return None
            plen = int.from_bytes(buf[2:4], 'big')
            off = 4
        elif plen == 127:
            if len(buf) < 10:
                return None
            plen = int.from_bytes(buf[2:10], 'big')
            off = 10
        if masked:
            if len(buf) < off + 4:
                return None
            off += 4
        if len(buf) < off + plen:
            return None
        payload = bytes(buf[off:off + plen])
        if masked:
            mask_key = bytes(buf[off - 4:off])
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        del self._buf[:off + plen]
        return (opcode, payload)

    @property
    def buffered(self) -> int:
        return len(self._buf)
