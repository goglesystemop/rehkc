"""Per-user XDG locations; source checkout and installed package share no bundled state."""
import os
from pathlib import Path

def config_dir():
    return Path(os.environ.get('REHKC_CONFIG_DIR') or Path(os.environ.get('XDG_CONFIG_HOME',Path.home()/'.config'))/'rehkc')

def data_dir():
    return Path(os.environ.get('REHKC_DATA_DIR') or Path(os.environ.get('XDG_DATA_HOME',Path.home()/'.local/share'))/'rehkc')
