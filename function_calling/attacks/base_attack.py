class Attack:
    def __init__(self, name, description):
        self.name = name
        self.description = description

    def execute(self, messages):
        raise NotImplementedError("Subclasses should implement this method.")