import os
import sys
sys.path.insert(0, os.path.abspath(".."))

project = "burp-frame"
author = "Gashaw Kidanu"
release = "1.0.0"

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
]

templates_path = ["_templates"]
exclude_patterns = []

html_theme = "furo"
