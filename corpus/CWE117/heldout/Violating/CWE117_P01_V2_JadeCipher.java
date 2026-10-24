import java.util.logging.Logger;

public class CWE117_P01_V2_JadeCipher {

    public void handleJadeCipher() {
        String data;
        while (true) {
            data = System.getenv("JADE_CIPHER_USER");
            break;
        }
        Logger jadeCipherLogger = Logger.getLogger("jadeCipher.audit");
        jadeCipherLogger.info("Login attempt for user " + data);
    }
}
