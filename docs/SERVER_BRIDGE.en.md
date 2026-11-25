# Server plaintext bridge SDK

[English user guide](guides/USER_GUIDE.en.md) · [Русская инструкция SDK](../src/server_bridge_sdk/README.md)

## Export and connect

1. Select **Sources → Server bridge** in the application and start capture.
2. Check the receiver status and click **Export server module…**.
3. Extract the ZIP. `bridge.json` contains this receiver's loopback endpoint and token. Export current configuration again after restarting the receiver.
4. Add the Java or Python adapter to your server. Submit a complete plaintext packet after decrypting a client request and before encrypting a server response.

The packet format is **u16 little-endian total length + opcode + payload**, 3–32768 bytes. `client` means C → S and `server` means S → C. Supported protocol names are `classic-h5`, `asterios-448` and `raw`.

## Python 3

```python
from bridge_sender import BridgeSender

sender = BridgeSender.from_file("bridge.json")
connection = sender.begin_connection("classic-h5")

# At the matching points in your server's packet pipeline:
connection.capture(full_decrypted_request, "client")
connection.capture(full_serialized_response, "server")

# During server shutdown:
sender.close()
```

Create a new connection object for each game connection. Keep one sender for the configured receiver. The adapter uses only the standard library.

## Java 8+

Copy `L2PlaintextBridge.java` into the server sources, adding your package declaration if needed. Read `endpoint` and `token` from `bridge.json` using your server's configuration loader.

```java
L2PlaintextBridge sender = new L2PlaintextBridge(endpoint, token, 1024);
L2PlaintextBridge.Connection connection = sender.beginConnection("classic-h5");

connection.capture(fullDecryptedRequest, "client");
connection.capture(fullSerializedResponse, "server");

// During server shutdown:
sender.close();
```

Compile the standalone adapter with:

```powershell
javac -source 8 -target 8 L2PlaintextBridge.java
```

The integration points depend on the server platform. The SDK requires you to connect these calls to its actual decrypt/serialize pipeline.

## Ordering and status

Each connection has one monotonically increasing sequence across both directions. A bounded background queue sends HTTP batches. The default capacity is 1024 packets; game threads copy and enqueue without waiting for HTTP. Dropped packets advance the sequence, so the next delivered packet exposes a gap.

The receiver selects one active SDK session at a time. Stop and restart capture to select another. Full inventory/skill lists should arrive through the normal game exchange after starting or recovering from a gap.

## Remote server

The receiver listens on loopback. Establish an SSH tunnel from the server to the PC running the monitor, then use the corresponding loopback endpoint in the server's configuration. For example, when the receiver reports port 16600:

```bash
ssh -N -L 16600:127.0.0.1:16600 user@monitor-pc
```

Use the actual receiver port and your existing SSH account. The bridge captures packets; queue replay and native actions use their own matching client transport.
