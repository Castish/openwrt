#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify this RAM40 release from exact artifacts and fresh evidence."""
from pathlib import Path
import runpy
runpy.run_path(str(Path(__file__).with_name("verify-artifacts.py")),run_name="__main__")
