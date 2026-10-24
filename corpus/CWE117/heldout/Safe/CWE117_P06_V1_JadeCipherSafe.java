import java.util.logging.Logger;

public class CWE117_P06_V1_JadeCipherSafe {

    public void handleJadeCipher() {
        String data;
        data = System.getenv("JADE_CIPHER_USER");
        (new CWE117_P06_V1_JadeCipherSafeSink()).logJadeCipher(data);
    }
}

class CWE117_P06_V1_JadeCipherSafeSink {
    public void logJadeCipher(String data) {
        Logger jadeCipherLogger = Logger.getLogger("jadeCipher.audit");
        jadeCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
