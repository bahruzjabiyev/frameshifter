## Anomaly Detection

The research project for which this tool has been developed for also involved anomaly detection. More specifically, we searched for abnormal HTTP/2-to-HTTP/1 conversions. The `/echo_server.py` program was used to capture HTTP/1 requests forwarded by reverse proxies. And the `anomaly_detection.py` was used to detect anomalies in the captured HTTP/1 requests.
