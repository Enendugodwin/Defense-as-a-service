import locale
import os
import queue
import secrets
import subprocess
import threading
import time


class PersistentShell:
    """Line-oriented shell session; intentionally not a PTY/interactive terminal."""

    def __init__(self, idle_timeout=900, command_timeout=30, max_output=32768):
        self.idle_timeout = idle_timeout
        self.command_timeout = command_timeout
        self.max_output = max_output
        self.process = None
        self.output_lines = None
        self.reader = None
        self.last_activity = time.monotonic()
        self.lock = threading.Lock()

    def _start(self):
        if os.name == "nt":
            command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"]
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            command = ["/bin/sh"]
            flags = 0
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
            bufsize=1,
            creationflags=flags,
        )
        output_lines = queue.Queue()
        self.process = process
        self.output_lines = output_lines
        self.reader = threading.Thread(
            target=self._read_output,
            args=(process, output_lines),
            daemon=True,
        )
        self.reader.start()
        self.last_activity = time.monotonic()

    def _read_output(self, process, output_lines):
        try:
            for line in process.stdout:
                output_lines.put(line)
        finally:
            output_lines.put(None)

    def is_idle_expired(self):
        return time.monotonic() - self.last_activity >= self.idle_timeout

    def close(self):
        with self.lock:
            self._close_locked()

    def _close_locked(self):
        process = self.process
        reader = self.reader
        self.process = None
        self.output_lines = None
        self.reader = None
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except OSError:
            pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        try:
            if process.stdout:
                process.stdout.close()
        except OSError:
            pass
        if reader and reader is not threading.current_thread():
            reader.join(timeout=1)

    def execute(self, command):
        if not isinstance(command, str) or not command.strip():
            raise ValueError("Session command cannot be empty")
        if len(command) > 2048 or "\n" in command or "\r" in command:
            raise ValueError("Session commands must be one line and no more than 2048 characters")

        with self.lock:
            if self.is_idle_expired():
                self._close_locked()
            if self.process is None or self.process.poll() is not None:
                self._close_locked()
                self._start()
            marker = "__SESSION_DONE_" + secrets.token_hex(12) + "__"
            if os.name == "nt":
                script = (
                    "$global:LASTEXITCODE = $null\r\n"
                    + command + "\r\n"
                    + "$__session_ok = $?\r\n"
                    + "$__session_status = if ($null -ne $global:LASTEXITCODE) "
                    + "{ [int]$global:LASTEXITCODE } elseif ($__session_ok) { 0 } else { 1 }\r\n"
                    + "[Console]::Out.WriteLine('" + marker + ":' + $__session_status)\r\n"
                )
            else:
                script = command + "\n__session_status=$?\nprintf '%s:%s\\n' '" + marker + "' \"$__session_status\"\n"
            try:
                self.process.stdin.write(script)
                self.process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._close_locked()
                raise RuntimeError("Persistent shell exited") from exc

            deadline = time.monotonic() + self.command_timeout
            output = []
            output_length = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._close_locked()
                    raise subprocess.TimeoutExpired(command, self.command_timeout, output="".join(output))
                try:
                    line = self.output_lines.get(timeout=remaining)
                except queue.Empty:
                    self._close_locked()
                    raise subprocess.TimeoutExpired(command, self.command_timeout, output="".join(output))
                if line is None:
                    self._close_locked()
                    raise RuntimeError("Persistent shell exited before completing the command")
                stripped = line.strip()
                if stripped.startswith(marker + ":"):
                    try:
                        status = int(stripped.split(":", 1)[1])
                    except ValueError:
                        status = 1
                    self.last_activity = time.monotonic()
                    return "".join(output), status
                if output_length < self.max_output:
                    kept = line[: self.max_output - output_length]
                    output.append(kept)
                    output_length += len(kept)