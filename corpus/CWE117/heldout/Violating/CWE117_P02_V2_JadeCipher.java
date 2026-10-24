import java.util.logging.Logger;

public class CWE117_P02_V2_JadeCipher {

    public void handleJadeCipher() {
        String dataCopy;
        {
            String data;
            if (true) {
                data = System.getenv("JADE_CIPHER_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeCipherLogger = Logger.getLogger("jadeCipher.audit");
            jadeCipherLogger.info("Login attempt for user " + data);
        }
    }
}
