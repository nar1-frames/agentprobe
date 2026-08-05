"""AgentProbe package.

Canonical, importable home for the pieces that used to live inline in the
monolithic `agentprobe_v11.py` script. Right now this holds only the
detection engine (`agentprobe.detection`); the scanner and reporter still
live at the repo root and import from here so there is a single source of
truth for the detector.
"""
