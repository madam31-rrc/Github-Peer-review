import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.*;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
 
/**
* VulnerableAppFixed.java
*
* Mitigations with OWASP Top 10 (2021) references.
* - No external deps beyond the JDK + JDBC driver.
* - Email is "sent" by logging (safe fallback) to avoid shell execution.
*
* OWASP categories addressed:
*  A02: Cryptographic Failures       (use HTTPS + timeouts)
*  A03: Injection                    (PreparedStatement; no shell)
*  A04: Insecure Design              (basic input validation)
*  A05: Security Misconfiguration    (timeouts, error handling)
*  A07: Identification & Auth Fail.  (no hard-coded secrets)
*  A09: Logging & Monitoring         (java.util.logging)
*/
public class VulnerableAppFixed {
 
    private static final Logger LOG = Logger.getLogger(VulnerableAppFixed.class.getName());
 
    // --- [Fix/A07] DO NOT hard-code DB secrets. Read from environment. ---
    private static final String DB_URL      = getenvOrNull("DB_URL");      // e.g., "jdbc:mysql://mydatabase.com/mydb"
    private static final String DB_USER     = getenvOrNull("DB_USER");     // e.g., "admin"
    private static final String DB_PASSWORD = getenvOrNull("DB_PASSWORD"); // e.g., "secret123"
 
    // Basic allowlist for a “name”: letters, spaces, hyphens, apostrophes; length 1..64
    private static final Pattern NAME_PATTERN = Pattern.compile("[A-Za-z\\s\\-']{1,64}");
 
    private static String getenvOrNull(String key) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? null : v;
    }
 
    // --- [Fix/A04] Input validation (allowlist + length cap) ---
    public static String getUserInput() throws IllegalArgumentException {
        try (Scanner sc = new Scanner(System.in)) {
            System.out.print("Enter your name: ");
            String raw = sc.nextLine();
            String name = raw == null ? "" : raw.trim();
            if (!NAME_PATTERN.matcher(name).matches()) {
                throw new IllegalArgumentException("Invalid name format.");
            }
            return name;
        }
    }
 
    // --- [Fix/A03] Safe “email” (no shell). Here we just log the message. ---
    // In real apps use JavaMail (external lib) or a trusted API client.
    public static void sendEmail(String to, String subject, String body) {
        // OWASP A03 – Avoid command injection (no Runtime.exec with untrusted input).
        LOG.info(() -> String.format("EMAIL (logged): to=%s, subject=%s, body=%s", to, subject, body));
    }
 
    // --- [Fix/A02, A05] HTTPS + timeouts + error handling ---
    public static String getData() {
        String httpsUrl = "https://insecure-api.com/get-data"; // assume TLS endpoint exists for demo
        StringBuilder result = new StringBuilder();
 
        HttpURLConnection conn = null;
        try {
            URL url = new URL(httpsUrl);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000); // A05 timeouts
            conn.setReadTimeout(5000);
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(false);
 
            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
 
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        result.append(line);
                    }
                }
            } else {
                LOG.warning("No response body from server. HTTP " + code);
            }
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Error fetching data", e);
        } finally {
            if (conn != null) conn.disconnect();
        }
 
        return result.toString();
    }
 
    // --- [Fix/A03, A05] PreparedStatement + minimal error handling ---
    public static void saveToDb(String data) {
        if (DB_URL == null || DB_USER == null || DB_PASSWORD == null) {
            throw new IllegalStateException("DB credentials are not set in environment (DB_URL/DB_USER/DB_PASSWORD).");
        }
 
        String sql = "INSERT INTO mytable (column1, column2) VALUES (?, ?)"; // A03: parameterized
 
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement ps = conn.prepareStatement(sql)) {
 
            ps.setString(1, data);
            ps.setString(2, "Another Value");
            ps.executeUpdate();
            LOG.info("Data saved to database.");
        } catch (SQLException e) {
            LOG.log(Level.SEVERE, "Database error", e); // A09 logging
        }
    }
 
    public static void main(String[] args) {
        try {
            String userInput = getUserInput();   // A04
            String data = getData();             // A02/A05
            saveToDb(data);                      // A03/A05/A07
            sendEmail("admin@example.com", "User Input", userInput); // A03 safe (no shell)
        } catch (IllegalArgumentException e) {
            LOG.severe("Invalid input: " + e.getMessage());
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Unexpected error", e);
        }
    }
}