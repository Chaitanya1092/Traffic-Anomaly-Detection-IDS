class BaseDetector:
    def __init__(self, config_manager, db_manager, logger):
        """
        Initialize the detector with config manager, database manager, and logger.
        """
        self.config = config_manager
        self.db = db_manager
        self.logger = logger

    def analyze(self, packet_info):
        """
        Analyze a single packet dictionary (parsed via PacketProcessor).
        If an anomaly is detected:
        1. Log the anomaly
        2. Insert the alert into the database
        3. Return a list of alert details (dicts) to be handled (e.g. notifications)
        """
        raise NotImplementedError("Detectors must implement the analyze method.")
