import json
import os

class MitreTagger:
    def __init__(self):
        mapping_file = os.path.join("config", "mitre_mapping.json")
        with open(mapping_file, "r") as f:
            self.mapping = json.load(f)

    def get_technique(self, behavior):
        """Returns technique ID, name, and tactic based on behavior."""
        return self.mapping.get(behavior, None)
