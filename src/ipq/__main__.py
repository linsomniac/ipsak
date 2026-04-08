# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "dnspython>=2.6",
#     "ipwhois>=1.3",
#     "httpx>=0.27",
#     "typer>=0.12",
#     "rich>=13.0",
# ]
# ///
"""Allow running as `python -m ipq` or `uv run src/ipq/__main__.py`."""

from ipq.cli import app

app()
