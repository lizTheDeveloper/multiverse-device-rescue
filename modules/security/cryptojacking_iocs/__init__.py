"""Data-only IOC package for cryptojacking detection.

Contains no ``Module`` class, so ``rescue.registry.discover_modules`` skips it
during discovery. The crypto_miner_persistence, win_crypto_miner_detect, and
browser_cryptojacking_check modules load this data through ``loader.py``.
"""
