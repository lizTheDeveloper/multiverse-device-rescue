"""Data-only helper package shared by the local-network modules.

Contains no ``Module`` class, so ``rescue.registry.discover_modules`` skips it.
``neighbors.py`` is loaded by path via ``rescue.runtime.load_content_module``.
"""
