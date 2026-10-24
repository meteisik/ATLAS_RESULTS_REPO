import java.util.logging.Logger;

public class CWE117_P03_V2_JadeCipherSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void logJadeCipher(String data) {
        Logger jadeCipherLogger = Logger.getLogger("jadeCipher.audit");
        jadeCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeCipher() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("JADE_CIPHER_USER");
        } else {
            data = null;
        }
        logJadeCipher(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
