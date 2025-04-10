import logging
import re
import json
import time
from collections import deque
from flask import Flask, jsonify, request


class NetworkMonitor:
    """
    Monitors network agent interactions for suspicious activity.
    """

    def __init__(self, known_agents, alert_handler=None, config=None):
        """
        Initializes the NetworkMonitor.

        Args:
            known_agents (list): A list of agent IDs to monitor.
            alert_handler (callable, optional): A function to handle alerts.
                                               Defaults to None (using the logger).
            config (dict, optional): Configuration dictionary with optional keys:
                - suspicious_activity_threshold (float): Default threshold.
                - decay_factor (float): Decay factor for historical interactions.
                - max_interactions (int): Maximum number of interactions to analyze.
                - rate_limit_window (int): Time window for rate limiting (in seconds).
        """
        self.known_agents = known_agents
        self.alert_handler = alert_handler or self._default_alert_handler
        self.config = config or {}
        self.suspicious_activity_threshold = self.config.get("suspicious_activity_threshold", 0.7)
        self.decay_factor = self.config.get("decay_factor", 0.8)
        self.max_interactions = self.config.get("max_interactions", 3)
        self.rate_limit_window = self.config.get("rate_limit_window", 300)
        self.keywords = {"malicious": 0.2, "unusual": 0.1, "suspicious": 0.1}
        self.known_agents_info = {}
        self.alert_log = {}
        self.logger = logging.getLogger(__name__)

    def _default_alert_handler(self, agent_id, score, message):
        """
        Default alert handler that logs a warning message.
        """
        self.logger.warning(message)

    def set_keywords(self, keywords):
        """
        Dynamically sets keywords and their weights.

        Args:
            keywords (dict): A dictionary of keywords and weights.
        """
        self.keywords = keywords

    def gather_interaction(self, agent_id, interaction):
        """
        Gathers and logs an interaction for a monitored agent.

        Args:
            agent_id (str): The agent's ID.
            interaction (str): The interaction text.
        """
        if agent_id not in self.known_agents_info:
            self.known_agents_info[agent_id] = {
                "interactions": deque(maxlen=10),
                "suspicious_score": 0.0,
            }
        self.known_agents_info[agent_id]["interactions"].append(interaction)

    def analyze_interactions(self):
        """
        Analyzes interactions for all monitored agents and triggers alerts if needed.
        """
        for agent_id, info in self.known_agents_info.items():
            suspicious_score = info.get("suspicious_score", 0.0)

            for i, interaction in enumerate(reversed(info["interactions"])):
                for keyword, weight in self.keywords.items():
                    if re.search(rf"\b{keyword}\b", interaction, re.IGNORECASE):
                        suspicious_score += weight * (self.decay_factor ** i)
            suspicious_score = min(suspicious_score, 1.0)  # Cap at 1.0

            # Trigger alert if suspicious activity is detected
            if suspicious_score > self.suspicious_activity_threshold:
                self._trigger_alert(agent_id, suspicious_score)
            info["suspicious_score"] = suspicious_score

    def _trigger_alert(self, agent_id, score):
        """
        Triggers an alert for suspicious activity.

        Args:
            agent_id (str): The agent's ID.
            score (float): The suspicious activity score.
        """
        now = time.time()
        if now - self.alert_log.get(agent_id, 0) < self.rate_limit_window:
            return  # Skip alert due to rate limiting

        self.alert_log[agent_id] = now
        message = f"Suspicious activity detected for agent {agent_id} with score {score:.2f}"
        self.alert_handler(agent_id, score, message)

    def save_state(self, file_path="network_monitor_state.json"):
        """
        Saves the current state to a file.

        Args:
            file_path (str): The file path to save the state.
        """
        with open(file_path, "w") as f:
            json.dump(self.known_agents_info, f)

    def load_state(self, file_path="network_monitor_state.json"):
        """
        Loads the state from a file.

        Args:
            file_path (str): The file path to load the state from.
        """
        with open(file_path, "r") as f:
            self.known_agents_info = json.load(f)


# Flask API to expose NetworkMonitor functionality
app = Flask(__name__)
network_monitor = NetworkMonitor(known_agents=["agent_1", "agent_2"])


@app.route("/agents", methods=["GET"])
def get_agents():
    """
    Returns the list of monitored agents.
    """
    return jsonify(list(network_monitor.known_agents_info.keys()))


@app.route("/agents/<agent_id>/interactions", methods=["POST"])
def post_interaction(agent_id):
    """
    Adds a new interaction for an agent.
    """
    data = request.json
    interaction = data.get("interaction")
    if not interaction:
        return jsonify({"error": "Interaction is required"}), 400
    network_monitor.gather_interaction(agent_id, interaction)
    return jsonify({"message": "Interaction added successfully"}), 201


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyzes all interactions for suspicious activity.
    """
    network_monitor.analyze_interactions()
    return jsonify({"message": "Analysis complete"}), 200


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True)
