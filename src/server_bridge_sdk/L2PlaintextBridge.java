import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** Java 8, standard library only. One sender per server, one Connection per game socket. */
public final class L2PlaintextBridge implements AutoCloseable {
    private final URI endpoint;
    private final String token;
    private final ArrayBlockingQueue<Record> queue;
    private final Thread worker;
    private volatile boolean closed;
    public final AtomicLong delivered = new AtomicLong();
    public final AtomicLong dropped = new AtomicLong();
    public final AtomicLong failedBatches = new AtomicLong();

    public L2PlaintextBridge(String endpoint, String token, int capacity) {
        this.endpoint = URI.create(endpoint);
        String host = this.endpoint.getHost();
        if (!"http".equals(this.endpoint.getScheme()) || !("127.0.0.1".equals(host) || "localhost".equals(host))
                || this.endpoint.getPort() < 1 || !"/v1/packets".equals(this.endpoint.getPath())
                || this.endpoint.getQuery() != null || this.endpoint.getFragment() != null || this.endpoint.getUserInfo() != null)
            throw new IllegalArgumentException("Expected local endpoint; use a loopback tunnel for a remote server");
        this.token = token;
        queue = new ArrayBlockingQueue<Record>(capacity);
        worker = new Thread(new Runnable() { public void run() { sendLoop(); } }, "l2-plaintext-bridge");
        worker.setDaemon(true);
        worker.start();
    }

    public Connection beginConnection(String protocol) {
        if (!("classic-h5".equals(protocol) || "asterios-448".equals(protocol) || "raw".equals(protocol)))
            throw new IllegalArgumentException("Unknown protocol");
        return new Connection(protocol);
    }

    public final class Connection {
        public final String sessionId = UUID.randomUUID().toString();
        private final String protocol;
        private long sequence;
        private Connection(String protocol) { this.protocol = protocol; }

        /** Call client after decrypt/reassembly, server before encrypt, with full u16-framed plaintext. */
        public synchronized boolean capture(byte[] fullPacket, String direction) {
            if (!("client".equals(direction) || "server".equals(direction)) || fullPacket.length < 3 || fullPacket.length > 32768
                    || ((fullPacket[0] & 255) | ((fullPacket[1] & 255) << 8)) != fullPacket.length)
                throw new IllegalArgumentException("Expected complete u16-framed plaintext packet");
            if (sequence >= 9007199254740991L) throw new IllegalStateException("Begin a new connection");
            ++sequence; // Loss is visible as a gap in the next delivered packet.
            if (closed || !queue.offer(new Record(this, sequence, direction, fullPacket.clone()))) {
                dropped.incrementAndGet();
                return false;
            }
            return true;
        }
    }

    private final class Record {
        final Connection connection;
        final long sequence;
        final String direction;
        final byte[] bytes;
        final double timestamp = System.currentTimeMillis() / 1000.0;
        Record(Connection c, long s, String d, byte[] b) { connection = c; sequence = s; direction = d; bytes = b; }
    }

    private static String hex(byte[] bytes) {
        final char[] alphabet = "0123456789abcdef".toCharArray();
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; ++i) { out[i * 2] = alphabet[(bytes[i] & 255) >>> 4]; out[i * 2 + 1] = alphabet[bytes[i] & 15]; }
        return new String(out);
    }

    private void sendLoop() {
        Record carried = null;
        while (!closed) {
            try {
                Record first = carried != null ? carried : queue.poll(100, TimeUnit.MILLISECONDS);
                carried = null;
                if (first == null) continue;
                List<Record> records = new ArrayList<Record>();
                records.add(first);
                int hexSize = first.bytes.length * 2;
                while (records.size() < 32 && hexSize < 800000) {
                    Record next = queue.poll();
                    if (next == null) break;
                    if (next.connection != first.connection || hexSize + next.bytes.length * 2 > 900000) { carried = next; break; }
                    records.add(next);
                    hexSize += next.bytes.length * 2;
                }
                sendBatch(first.connection, records);
            } catch (InterruptedException stop) {
                if (!closed) Thread.currentThread().interrupt();
                break;
            }
        }
        dropped.addAndGet(queue.size() + (carried == null ? 0 : 1));
        queue.clear();
    }

    private void sendBatch(Connection connection, List<Record> records) {
        StringBuilder body = new StringBuilder();
        body.append("{\"schema\":1,\"session_id\":\"").append(connection.sessionId)
            .append("\",\"protocol\":\"").append(connection.protocol).append("\",\"packets\":[");
        for (int i = 0; i < records.size(); ++i) {
            Record r = records.get(i);
            if (i > 0) body.append(',');
            body.append("{\"sequence\":").append(r.sequence).append(",\"direction\":\"").append(r.direction)
                .append("\",\"hex\":\"").append(hex(r.bytes)).append("\",\"timestamp\":").append(r.timestamp).append('}');
        }
        body.append("]}");
        HttpURLConnection client = null;
        try {
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            client = (HttpURLConnection) endpoint.toURL().openConnection();
            client.setConnectTimeout(1000);
            client.setReadTimeout(2000);
            client.setInstanceFollowRedirects(false);
            client.setRequestMethod("POST");
            client.setRequestProperty("Content-Type", "application/json");
            client.setRequestProperty("X-L2-Bridge-Token", token);
            client.setDoOutput(true);
            client.setFixedLengthStreamingMode(bytes.length);
            try (OutputStream output = client.getOutputStream()) { output.write(bytes); }
            if (client.getResponseCode() != 200) throw new java.io.IOException("Batch rejected");
            // Receiver's 200 contract means the whole batch has committed.
            try (InputStream input = client.getInputStream()) {
                byte[] buffer = new byte[1024];
                int total = 0, read;
                while ((read = input.read(buffer)) != -1) { total += read; if (total > 4096) throw new java.io.IOException("Unexpected response"); }
            }
            delivered.addAndGet(records.size());
        } catch (Exception failure) {
            // Never retry an ambiguous timeout: the receiver may already have committed.
            dropped.addAndGet(records.size());
            failedBatches.incrementAndGet();
        } finally { if (client != null) client.disconnect(); }
    }

    @Override public void close() {
        closed = true;
        worker.interrupt();
        try { worker.join(4000); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
    }
}
