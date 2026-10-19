"""Data-only helper package shared by the connection checks and the connection watch.

Contains no ``Module`` class, so ``rescue.registry.discover_modules`` skips it.
``collect.py`` is loaded by path via ``rescue.runtime.load_content_module``.
"""
