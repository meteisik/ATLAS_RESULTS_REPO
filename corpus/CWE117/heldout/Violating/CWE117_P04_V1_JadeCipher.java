import java.util.logging.Logger;

public class CWE117_P04_V1_JadeCipher {

    private String readJadeCipher() {
        String data;
        data = System.getenv("JADE_CIPHER_USER");
        return data;
    }

    public void handleJadeCipher() {
        String data = readJadeCipher();
        Logger jadeCipherLogger = Logger.getLogger("jadeCipher.audit");
        jadeCipherLogger.info("Login attempt for user " + data);
    }
}
