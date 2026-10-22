# Frequently Asked Questions (FAQ)

Here are the answers to the most frequently asked questions about the Stitch Sentinel EDR Agent.

---

### Q1: Can I deploy this agent on Linux?
**A**: The backend dashboard and APIs can be run on any platform (Linux, Windows, macOS, Docker). The monitoring agent itself is designed for Windows hosts (using Windows-specific `pywin32` API bindings), but includes full cross-platform fallback mock data handlers so that developers can test and refine the agent's behavior on any development OS.

### Q2: How does the agent handle offline scenarios?
**A**: When the endpoint is offline or the backend server is unreachable, the agent automatically buffers telemetry events (up to 500 records) in a local in-memory queue. Once the network connection is restored, the buffer is flushed and sent to the Django backend.

### Q3: What is the impact of the EDR agent on system performance?
**A**: Stitch Sentinel is highly optimized:
- Process polling uses lightweight `psutil` iterative checks.
- Event log reads are incremental.
- Default CPU/RAM consumption is minimal (typically <1% CPU and <15MB RAM).

### Q4: How do I change the polling interval of the agent?
**A**: Adjust the interval values inside `config/config.json` (e.g. `process_interval_seconds` or `systemhealth_interval_seconds`) or update settings globally via the **Settings** view in the Web SOC Dashboard.
