"""Demo source file with planted (fake but checksum-valid) CN-PII.

This is the file the RedactGate demo points an agent at. It mixes ordinary
business logic — which you *want* a coding agent to read — with hard-coded
Chinese PII that must never leave the machine:

    身份证号 / 手机号 / 银行卡 / 统一社会信用代码 / 内网域名

IMPORTANT: every value below is **synthetic**. Each id card / bank card / USCC
was fabricated by running its checksum forward (so it passes GB 11643 / Luhn /
mod-31) — it is NOT a real person's data. The point of the demo is that
RedactGate masks exactly these fields (``110101199003078515`` ->
``1101**********8515``) while leaving the surrounding logic byte-for-byte intact,
so the agent still gets the code and the PII never egresses.

Run the demo::

    redactgate scan examples/demo-repo/leaky.py      # list every hit
    redactgate proxy --stdin < examples/demo-repo/leaky.py   # masked egress
"""

from __future__ import annotations

# --- Connection config: an internal host the agent should never see leak ----
DB_HOST = "pg-master.db.corp"            # intranet_domain
CACHE_HOST = "10.12.0.45"                # intranet_domain (RFC1918)
API_GATEWAY = "https://api.example.com"  # public — NOT masked

# --- Seed / fixture data with planted PII (all synthetic, checksum-valid) ----
SEED_CUSTOMER = {
    "name": "示例用户",
    "id_card": "110101199003078515",      # 身份证 — GB 11643 valid
    "phone": "13800138000",               # 手机号 — number plan
    "bank_card": "6222021000112230",      # 银行卡 — Luhn valid
    "order_id": "110101199003078500",     # 18 digits BUT bad check digit -> NOT masked
}

COMPANY = {
    "name": "示例科技有限公司",
    "uscc": "91110108MA01ABCD1E",         # 统一社会信用代码 — mod-31 valid
    "contact_phone": "13912345678",       # 手机号 — number plan
}


# --- Business logic the agent SHOULD see (must survive redaction untouched) --
def settle_order(amount_cents: int, fee_bps: int = 60) -> int:
    """Settle an order: apply a basis-point fee and round to the nearest cent.

    This is exactly the kind of logic you want the coding agent to read and
    improve — nothing here is PII, so RedactGate leaves every byte in place.
    """
    fee = (amount_cents * fee_bps) // 10_000
    net = amount_cents - fee
    return max(net, 0)


def mask_for_display(card: str) -> str:
    """A naive display mask the team wrote by hand (unrelated to RedactGate)."""
    return card[:4] + "*" * (len(card) - 8) + card[-4:]


if __name__ == "__main__":
    print(f"settle_order(100_00) = {settle_order(100_00)}")
    print(f"db host = {DB_HOST}, cache = {CACHE_HOST}")
    print(f"seed id_card display = {mask_for_display(SEED_CUSTOMER['id_card'])}")
