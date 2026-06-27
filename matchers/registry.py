"""
Matcher registry / plugin loader
===============================

Collects all built-in matchers plus any third-party matcher plugins.

A plugin is any Python module placed in ``matchers/plugins/`` that defines a
module-level ``MATCHERS`` list (or ``register()`` returning such a list) of
``BaseMatcher`` instances. They are discovered automatically at startup, so
adding a brand-new attack type to LogicBreaker AI is a drop-in: write one
file, no engine changes.
"""

import importlib
import os
import pkgutil

from matchers.builtin import ALL_MATCHERS as _BUILTIN


def load_matchers(enabled_ids=None):
    matchers = list(_BUILTIN)

    # discover plugins
    plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
    if os.path.isdir(plugins_dir):
        for mod_info in pkgutil.iter_modules([plugins_dir]):
            try:
                module = importlib.import_module(f"matchers.plugins.{mod_info.name}")
            except Exception as e:  # pragma: no cover
                print(f"[plugin] failed to load {mod_info.name}: {e}")
                continue
            found = getattr(module, "MATCHERS", None)
            if found is None and hasattr(module, "register"):
                found = module.register()
            if found:
                matchers.extend(found)

    if enabled_ids:
        matchers = [m for m in matchers if m.id in enabled_ids]
    return matchers


def matcher_catalogue():
    return [{"id": m.id, "name": m.name, "cwe": m.cwe,
             "languages": sorted(m.languages) or ["all"]}
            for m in load_matchers()]
