# burp-frame/docs/conf.py

import os
import sys
# Add the project base directory to sys.path so we can import our package
current_dir = os.path.dirname(__file__) # .../burp-frame/docs/
project_base_dir = os.path.abspath(os.path.join(current_dir, '..')) # .../burp-frame/
sys.path.insert(0, project_base_dir)

# Project information
project = 'burp-frame'
copyright = '2025, Gashaw Kidanu'
author = 'Gashaw Kidanu'
# The short X.Y version
version = '1.0' # Should ideally pull from your scripts/__init__.py __version__
# The full version, including alpha/beta/rc tags
release = '1.0.0' # Should ideally pull from your scripts/__init__.py __version__

# General configuration
extensions = [
    'sphinx.ext.autodoc',     # To automatically generate docs from docstrings
    'sphinx.ext.napoleon',    # For Google or NumPy style docstrings
    'sphinx.ext.todo',        # If you want to use todo notes
    'sphinx.ext.viewcode',    # To link to the source code
    'sphinx.ext.intersphinx', # For linking to other Sphinx docs
    # If you want to write docs in Markdown:
    'myst_parser',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
html_theme = 'sphinx_rtd_theme' # Recommended theme for Read the Docs
# html_static_path = ['_static'] # If you have static files like images

# Autodoc configuration
autodoc_member_order = 'bysource' # Or 'alphabetical', 'groupwise'

# Intersphinx mapping (optional, for linking to Python docs etc.)
# intersphinx_mapping = {
#     'python': ('https://docs.python.org/3', None),
#     'frida': ('https://frida.re/docs/python-api/', None), # Example
# }

# Source suffix (if you use .md for some files)
# source_suffix = {
#     '.rst': 'restructuredtext',
#     '.txt': 'restructuredtext',
#     '.md': 'markdown',
# }
