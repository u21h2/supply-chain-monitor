# Copyright 2026 Elastic N.V.
# Licensed under the MIT License. See LICENSE file in the project root for details.

from http_utils import get_json

URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
TOP_N = 1000


def fetch_top_packages(url: str = URL, top_n: int = TOP_N) -> list[dict]:
    data = get_json(url, timeout=30)

    print(f"Last updated: {data['last_update']}")
    print(f"Total packages in dataset: {len(data['rows']):,}")

    rows = data["rows"][:top_n]
    print(f"\nTop {top_n} packages by monthly downloads:\n")
    print(f"{'Rank':<6} {'Package':<40} {'Downloads':>15}")
    print("-" * 63)
    for i, row in enumerate(rows, 1):
        print(f"{i:<6} {row['project']:<40} {row['download_count']:>15,}")

    return rows


if __name__ == "__main__":
    fetch_top_packages()
