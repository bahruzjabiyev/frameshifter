## Anomaly Detection

The research project for which this tool has been developed also involved the detection of abnormal HTTP/2-to-HTTP/1 conversions. The `/echo_server.py` program was used to capture HTTP/1 requests forwarded by reverse proxies. And the `anomaly_detection.py` was run on the captured requests to detect abnormal conversions.
