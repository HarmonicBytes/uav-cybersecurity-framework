
from block import Block


def create_genesis_block():
    """
    Deterministic genesis block for the
    experimental replicated ledger.
    """

    genesis = Block(
        index=0,
        timestamp=0.0,
        previous_hash="0" * 64,
        event={"type": "GENESIS"},
    )

    genesis.seal()
    return genesis


TRUSTED_GENESIS_HASH = (
    create_genesis_block().block_hash
)
