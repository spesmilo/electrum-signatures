#!/usr/bin/env python3
"""Verify signature files against the binaries on download.electrum.org.

Signature files are laid out as

    <version>/<file>/<file>.<signer>.asc

e.g. 4.8.3/Electrum-4.8.3.tar.gz/Electrum-4.8.3.tar.gz.Emzy.asc

For every signature file, <file> is downloaded from
https://download.electrum.org/<version>/<file> and verified with the key in
pubkeys/<signer>.asc of the spesmilo/electrum repository.
Signatures made by an expired or revoked key fail.

Usage:
    # verify the signature files added or modified on the current branch
    # (this is what CI runs for pull requests)
    contrib/verify_signatures.py --diff-base origin/master

    # verify specific signature files
    contrib/verify_signatures.py 4.8.3/*/*.asc

Requirements: python3, git, gpg, gpgv.
"""

import argparse
import http.client
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, NamedTuple, Tuple

DOWNLOAD_URL = "https://download.electrum.org/"
PUBKEYS_URL = "https://raw.githubusercontent.com/spesmilo/electrum/master/pubkeys/"
# download.electrum.org (cloudflare) rejects the default Python-urllib user agent
USER_AGENT = "electrum-signatures-verifier (+https://github.com/spesmilo/electrum-signatures)"
DOWNLOAD_ATTEMPTS = 3

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SIG_PATH_RE = re.compile(
    r"(?P<version>[0-9]+(?:\.[0-9]+)+(?:[a-z]+[0-9]*)?)/"
    r"(?P<filename>[A-Za-z0-9][A-Za-z0-9._+-]*)/"
    r"(?P=filename)\.(?P<signer>[A-Za-z0-9_-]+)\.asc")


class SigFile(NamedTuple):
    path: str  # relative to REPO_ROOT
    version: str
    filename: str
    signer: str


class VerificationError(Exception):
    def __init__(self, message: str, details: str = ""):
        super().__init__(message)
        self.message = message
        self.details = details  # e.g. gpgv output, only shown in the log


def log(msg: str = "") -> None:
    print(msg, flush=True)


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def changed_files(diff_base: str) -> Tuple[List[str], List[str]]:
    """Return the (added or modified, deleted) files between merge-base(diff_base, HEAD) and HEAD."""
    out = subprocess.run(
        ["git", "-C", REPO_ROOT, "diff", "--name-status", "--no-renames", "-z", f"{diff_base}...HEAD", "--"],
        stdout=subprocess.PIPE, check=True).stdout
    fields = out.split(b"\0")[:-1]
    changed, deleted = [], []
    for status, path in zip(fields[0::2], fields[1::2]):
        (deleted if status == b"D" else changed).append(os.fsdecode(path))
    return changed, deleted


def download(url: str, dest: str) -> None:
    """Download url to dest, retrying on transient errors."""
    attempts = 1 if url.startswith("file:") else DOWNLOAD_ATTEMPTS
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as f:
                shutil.copyfileobj(resp, f, 1 << 20)
                expected = resp.headers.get("Content-Length") or ""
                if re.fullmatch(r"[0-9]+", expected) and int(expected) != f.tell():
                    raise OSError(f"incomplete download: got {f.tell()} of {expected} bytes")
            return
        except urllib.error.HTTPError as e:
            error = f"HTTP {e.code} {e.reason}"
            if e.code < 500 and e.code not in (408, 429):
                attempts = attempt  # not a transient error, don't retry
        except urllib.error.URLError as e:
            error = str(e.reason)
        except (http.client.HTTPException, OSError) as e:
            error = repr(e)
        if attempt == attempts:
            raise VerificationError(f"could not download {url}: {error}")
        log(f"  download of {url} failed ({error}), retrying in {5 * attempt}s")
        time.sleep(5 * attempt)


class Keyrings:
    """Builds a separate gpgv keyring for every signer, from pubkeys/<signer>.asc."""

    def __init__(self, pubkeys_url: str, workdir: str):
        self.pubkeys_url = pubkeys_url
        self.workdir = workdir
        self.cache = {}  # signer -> keyring path or VerificationError

    def get(self, signer: str) -> str:
        if signer not in self.cache:
            try:
                self.cache[signer] = self._load(signer)
            except VerificationError as e:
                self.cache[signer] = e
        if isinstance(self.cache[signer], VerificationError):
            raise self.cache[signer]
        return self.cache[signer]

    def _load(self, signer: str) -> str:
        url = urllib.parse.urljoin(self.pubkeys_url, urllib.parse.quote(signer) + ".asc")
        homedir = tempfile.mkdtemp(dir=self.workdir)
        keyfile = os.path.join(homedir, "key.asc")
        keyring = os.path.join(homedir, "keyring.gpg")
        try:
            download(url, keyfile)
        except VerificationError as e:
            raise VerificationError(f"no pubkey for signer {signer!r} ({e.message})") from None
        # --no-autostart: importing public keys does not need gpg-agent
        gpg = ["gpg", "--homedir", homedir, "--batch", "--quiet", "--no-autostart"]
        try:
            for args in (["--import", keyfile], ["--output", keyring, "--export"]):
                p = run(gpg + args)
                if p.returncode != 0:
                    raise VerificationError(f"could not import {url}", details=p.stderr.decode(errors="replace"))
        finally:
            # gpg creates an (empty) socket directory for the homedir in /run/user/<uid>/gnupg/
            run(["gpgconf", "--homedir", homedir, "--remove-socketdir"])
        return keyring


def gpgv_verify(keyring: str, sig: SigFile, data_path: str) -> str:
    """Verify sig against data_path, and return the fingerprint of the signing key."""
    p = run(["gpgv", "--homedir", os.path.dirname(keyring), "--keyring", keyring, "--status-fd", "1",
             "--", os.path.join(REPO_ROOT, sig.path), data_path])
    output = p.stderr.decode(errors="replace").strip()
    # gpgv exits with 0 for good signatures made by expired or revoked keys,
    # so the status lines have to be checked
    status = [line.split(" ")[1:] for line in p.stdout.decode(errors="replace").splitlines()
              if line.startswith("[GNUPG:] ")]
    for keyword, *args in status:
        if keyword == "BADSIG":
            raise VerificationError("BAD signature: it does not match the file on download.electrum.org", output)
        if keyword == "ERRSIG" and len(args) >= 6:
            key = args[6] if len(args) > 6 and args[6] != "-" else args[0]
            if args[5] == "9":  # missing public key
                raise VerificationError(
                    f"signature was made by key {key}, which is not in pubkeys/{sig.signer}.asc", output)
            raise VerificationError(f"cannot check signature made by key {key}", output)
        if keyword == "EXPKEYSIG":
            raise VerificationError(f"the key in pubkeys/{sig.signer}.asc has expired; "
                                    f"the signer needs to publish an updated key in spesmilo/electrum", output)
        if keyword == "REVKEYSIG":
            raise VerificationError(f"the key in pubkeys/{sig.signer}.asc is revoked", output)
        if keyword == "EXPSIG":
            raise VerificationError("the signature has expired", output)
    keywords = [keyword for keyword, *args in status]
    fingerprints = [args[9] for keyword, *args in status if keyword == "VALIDSIG" and len(args) >= 10]
    nsigs = keywords.count("NEWSIG")
    if nsigs == 0:
        raise VerificationError(
            "no detached signature found (create one with 'gpg --armor --detach-sign')", output)
    if p.returncode != 0 or keywords.count("GOODSIG") != nsigs or len(fingerprints) != nsigs:
        raise VerificationError(f"could not verify the signature (gpgv exit code {p.returncode})", output)
    return ", ".join(sorted(set(fingerprints)))


def verify(sigs: List[SigFile], download_url: str, pubkeys_url: str) -> List[Tuple[str, str]]:
    """Verify sigs, downloading every binary once. Returns the failures as (path, message)."""
    failures = []

    def fail(sig: SigFile, e: VerificationError) -> None:
        failures.append((sig.path, e.message))
        log(f"  FAIL {os.path.basename(sig.path)}\n       {e.message}")
        for line in e.details.splitlines():
            log(f"       | {line}")

    groups = {}
    for sig in sigs:
        groups.setdefault((sig.version, sig.filename), []).append(sig)
    with tempfile.TemporaryDirectory(prefix="verify-sigs-") as workdir:
        keyrings = Keyrings(pubkeys_url, workdir)
        binary = os.path.join(workdir, "binary")
        for (version, filename), group in sorted(groups.items()):
            log(f"\n[{version}/{filename}]")
            pending = []
            for sig in sorted(group):
                try:
                    pending.append((sig, keyrings.get(sig.signer)))
                except VerificationError as e:
                    fail(sig, e)
            if not pending:
                continue
            url = urllib.parse.urljoin(download_url, urllib.parse.quote(f"{version}/{filename}"))
            log(f"  downloading {url}")
            try:
                download(url, binary)
            except VerificationError as e:
                for sig, _ in pending:
                    fail(sig, e)
                continue
            for sig, keyring in pending:
                try:
                    fingerprint = gpgv_verify(keyring, sig, binary)
                    log(f"  OK   {os.path.basename(sig.path)}\n"
                        f"       good signature by {sig.signer}, key {fingerprint}")
                except VerificationError as e:
                    fail(sig, e)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify signature files against the binaries on download.electrum.org, "
                    "using the signers' pubkeys from the spesmilo/electrum repository.")
    parser.add_argument("paths", nargs="*", metavar="SIGFILE", help="signature file to verify")
    parser.add_argument("--diff-base", metavar="REV",
                        help="verify the files added or modified in HEAD since its merge-base with REV")
    parser.add_argument("--download-url", default=DOWNLOAD_URL,
                        help="base URL of the binaries (default: %(default)s)")
    parser.add_argument("--pubkeys-url", default=PUBKEYS_URL,
                        help="base URL of the signer pubkeys (default: %(default)s)")
    args = parser.parse_args()
    if bool(args.paths) == bool(args.diff_base):
        parser.error("pass either --diff-base or one or more SIGFILEs")

    failures = []  # (path, message)
    warnings = []  # (path, message)
    if args.diff_base:
        paths, deleted = changed_files(args.diff_base)
        for path in deleted:
            warnings.append((path, "signature file deleted" if path.endswith(".asc") else "file deleted"))
    else:
        for path in args.paths:
            if not os.path.isfile(path):
                parser.error(f"{path}: no such file")
        paths = [os.path.relpath(os.path.abspath(path), REPO_ROOT).replace(os.sep, "/") for path in args.paths]

    sigs = []
    for path in paths:
        m = SIG_PATH_RE.fullmatch(path)
        if m:
            sigs.append(SigFile(path, m["version"], m["filename"], m["signer"]))
        elif not args.diff_base or path.endswith(".asc") or re.match(r"[0-9]", path):
            failures.append((path, "unexpected file: signature files must be named "
                                   "<version>/<file>/<file>.<signer>.asc"))
        else:
            warnings.append((path, "file other than a signature changed"))
    for path, message in warnings:
        log(f"WARNING {path}: {message}")
    for path, message in failures:
        log(f"FAIL {path}: {message}")

    sig_failures = []
    if sigs:
        log(f"Verifying {len(sigs)} signature file(s)")
        sig_failures = verify(sigs, args.download_url.rstrip("/") + "/", args.pubkeys_url.rstrip("/") + "/")
    else:
        log("No signature files to verify.")
    failures += sig_failures

    if os.environ.get("GITHUB_ACTIONS") == "true":  # show them on the pull request page
        for path, message in failures:
            print(f"::error file={path}::{message}")
        for path, message in warnings:
            print(f"::warning file={path}::{message}")
    log(f"\n{len(sigs) - len(sig_failures)} signature file(s) OK, {len(failures)} failed, "
        f"{len(warnings)} warning(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
