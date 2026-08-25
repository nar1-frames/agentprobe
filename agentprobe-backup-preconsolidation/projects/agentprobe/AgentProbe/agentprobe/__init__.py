"""AgentProbe — canonical package.

The research pipeline (research/) and the scanner both import their detection
logic from `agentprobe.detection`, so a fix lands in exactly one place instead
of being copied across agentprobe_v01..v11.
"""
