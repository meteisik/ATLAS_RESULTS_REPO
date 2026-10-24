import java.util.logging.Logger;

public class CWE117_P05_V1_JadeCipher {

    private String jadeCipherData;

    private void logJadeCipher() {
        String data = jadeCipherData;
        Logger jadeCipherLogger = Logger.getLogger("jadeCipher.audit");
        jadeCipherLogger.info("Login attempt for user " + data);
    }

    public void handleJadeCipher() {
        String data;
        data = System.getenv("JADE_CIPHER_USER");
        jadeCipherData = data;
        logJadeCipher();
    }
}
