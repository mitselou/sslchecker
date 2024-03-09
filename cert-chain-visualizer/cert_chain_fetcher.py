from __future__ import annotations

import subprocess
import re
import json
from pathlib import Path
import argparse
from typing import Any
from dataclasses import dataclass


HTTPS_PORT = 443


DEPTH_RE = re.compile(r"^depth=(?P<depth>\d+)", flags=re.MULTILINE)
COUNTRY_RE = re.compile(r",? C ?= ?(?P<value>[^,]+|\"[^\"]+\")")
STATE_RE = re.compile(r",? ST ?= ?(?P<value>[^,]+|\"[^\"]+\")")
LOCALITY_RE = re.compile(r",? L ?= ?(?P<value>[^,]+|\"[^\"]+\")")
ORGANIZATIONAL_UNIT_RE = re.compile(r",? OU ?= ?(?P<value>[^,]+|\"[^\"]+\")")
ORGANIZATION_RE = re.compile(r",? O ?= ?(?P<value>[^,]+|\"[^\"]+\")")
CANONICAL_NAME_RE = re.compile(r",? CN ?= ?(?P<value>[^,]+|\"[^\"]+\")")


@dataclass
class CertificateData:
    canonical_name: str | None = None
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    organization: str | None = None
    organizational_unit: str | None = None

    def to_json(self) -> dict[str, str]:
        out = {}
        if self.canonical_name is not None:
            out["canonical_name"] = self.canonical_name
        if self.country is not None:
            out["country"] = self.country
        if self.state is not None:
            out["state"] = self.state
        if self.locality is not None:
            out["locality"] = self.locality
        if self.organization is not None:
            out["organization"] = self.organization
        if self.organizational_unit is not None:
            out["organizational_unit"] = self.organizational_unit
        return out


class CertDataEncoder(json.JSONEncoder):
    def default(self, obj: object) -> Any:
        if isinstance(obj, CertificateData):
            return obj.to_json()
        return super().default(obj)


class CertChainFetcherException(Exception):
    pass


def get_cert_chain(host: str, port: int) -> list[CertificateData]:
    cmd = (
        f"openssl s_client -connect {host}:{port} -servername {host} -showcerts </dev/null"
        " | openssl crl2pkcs7 -nocrl"
        " | openssl pkcs7 -noout -print_certs"
    )
    proc = subprocess.run(cmd, capture_output=True, shell=True, text=True)
    if "errno" in proc.stderr:
        raise CertChainFetcherException("openssl command failed", proc.stderr)
    lines = proc.stderr.splitlines()

    if DEPTH_RE.search(proc.stderr) is None:
        raise CertChainFetcherException("couldn't determine depth", proc.stderr)

    cert_chain = {}
    max_depth: int = -1
    for line in lines:
        depth_mo = DEPTH_RE.search(line)
        if depth_mo is None:
            continue
        depth = int(depth_mo.group("depth"))
        max_depth = max(max_depth, depth)
        # Match the certificate properties with RegEx
        canonical_name_mo = CANONICAL_NAME_RE.search(line)
        country_mo = COUNTRY_RE.search(line)
        state_mo = STATE_RE.search(line)
        locality_mo = LOCALITY_RE.search(line)
        organization_mo = ORGANIZATIONAL_UNIT_RE.search(line)
        organizational_unit_mo = ORGANIZATION_RE.search(line)
        # Extract the captured property values from the matched objects
        canonical_name = (
            canonical_name_mo.group("value") if canonical_name_mo is not None else None
        )
        country = country_mo.group("value") if country_mo is not None else None
        state = state_mo.group("value") if state_mo is not None else None
        locality = locality_mo.group("value") if locality_mo is not None else None
        organization = (
            organization_mo.group("value") if organization_mo is not None else None
        )
        organizational_unit = (
            organizational_unit_mo.group("value")
            if organizational_unit_mo is not None
            else None
        )
        # Add the certificate to the chain
        cert = CertificateData(
            canonical_name=canonical_name,
            country=country,
            state=state,
            locality=locality,
            organization=organization,
            organizational_unit=organizational_unit,
        )
        cert_chain[depth] = cert
    if (len(cert_chain) != max_depth + 1) or (
        set(cert_chain.keys()) != set(range(len(cert_chain)))
    ):
        raise CertChainFetcherException(
            "incorrect number of certificates parsed", proc.stderr
        )
    return [
        cert_data
        for _depth, cert_data in sorted(
            cert_chain.items(), key=lambda tup: tup[0], reverse=True
        )
    ]


def transform_tree(cert_data: dict[str, Any], tree: dict[Any, Any]) -> dict[str, Any]:
    output = {
        "id": cert_data["canonical_name"],
        "properties": cert_data,
        "children": [],
    }
    for cert_data_frozenset, subtree in tree.items():
        cert_data = dict(cert_data_frozenset)
        output["children"].append(transform_tree(cert_data, subtree))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetches the certificate chain for the given domains"
    )
    parser.add_argument("--hosts", type=Path, default="top_100_domains.txt")
    parser.add_argument("--port", type=int, default=HTTPS_PORT)
    parser.add_argument("--output", type=Path, default="cert-tree-data.json")
    args = parser.parse_args()
    hosts_path, out_path, port = args.hosts, args.output, args.port

    domains = hosts_path.read_text().split("\n")

    cert_chains = {}
    unreachable_domains = []
    for domain in domains:
        try:
            cert_chain = get_cert_chain(domain, port)
            cert_chains[domain] = cert_chain
        except CertChainFetcherException as exc:
            print(domain)
            print(exc.args[0])
            print(exc.args[1])
            print()
            unreachable_domains.append(domain)

    tree: Any = {}
    for cert_chain in cert_chains.values():
        insert_point = tree
        for part in cert_chain:
            part_frozenset = frozenset(part.to_json().items())
            if part_frozenset not in insert_point:
                insert_point[part_frozenset] = {}
            insert_point = insert_point[part_frozenset]
    data = transform_tree({"canonical_name": "-"}, tree)

    json_str = json.dumps(data, cls=CertDataEncoder, indent=4, sort_keys=True)
    out_path.write_text(json_str)


if __name__ == "__main__":
    main()
