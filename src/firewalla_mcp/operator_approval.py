"""Read-only operator approvals with a separate durable consumption ledger.

No MCP method creates these files. The operator UID must differ from the server.
This authenticates the file issuer, not a model's claim about chat confirmation.
"""
import json
import os
from pathlib import Path
import stat
import time


class ApprovalRequired(ValueError):
    pass


class OperatorApproval:
    def __init__(self, config):
        self.directory = Path(config.approval_directory or '')
        self.ledger = Path(config.approval_consumed_directory or '')
        self.issuer = config.trusted_approval_uid

    def validate_storage(self):
        if not self.directory.is_absolute() or not self.ledger.is_absolute() or self.directory == self.ledger:
            raise ValueError('Separate absolute approval and consumption directories required')
        if self.issuer == os.getuid():
            raise ValueError('Approval issuer must be separate from the MCP process')
        approval = self.directory.lstat(); ledger = self.ledger.lstat()
        if (not stat.S_ISDIR(approval.st_mode) or approval.st_uid != self.issuer
                or approval.st_mode & 0o022 or os.access(self.directory, os.W_OK)):
            raise ValueError('Operator approval directory must be issuer-owned and not writable by MCP')
        if not stat.S_ISDIR(ledger.st_mode) or ledger.st_uid != os.getuid() or stat.S_IMODE(ledger.st_mode) != 0o700:
            raise ValueError('Consumption ledger must be private to the MCP process')

    def consume(self, plan):
        self.validate_storage()
        if time.time() >= plan['expires_at']:
            raise ValueError('Approval expired')
        path = self.directory / (plan['plan_id'] + '.json')
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise ApprovalRequired('Missing trusted operator approval') from None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.issuer or info.st_nlink != 1
                    or info.st_mode & 0o022 or info.st_size > 4096):
                raise ValueError('Approval is not an immutable operator-owned regular file')
            raw = os.read(fd, 4097)
            if len(raw) != info.st_size: raise ValueError('Approval changed while reading')
            approval = json.loads(raw)
        finally: os.close(fd)
        expected = dict(plan_id=plan['plan_id'],digest=plan['digest'],expires_at=plan['expires_at'],approved=True)
        if (approval != expected or approval.get('approved') is not True
                or type(approval.get('expires_at')) is not int):
            raise ValueError('Operator approval does not match the exact preview')
        # The approval mount stays read-only. O_EXCL claims the action exactly once,
        # including simultaneous callers or a process restart after uncertainty.
        if time.time() >= plan["expires_at"]: raise ValueError("Approval expired")
        marker = self.ledger / (plan['plan_id'] + '.used')
        try:
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise ValueError('Approval already consumed') from None
        try:
            os.write(fd, json.dumps({'plan_id':plan['plan_id'],'digest':plan['digest']}).encode())
            os.fsync(fd)
        finally: os.close(fd)
        fd = os.open(self.ledger, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
