import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenCipher {

    public void handleGoldenCipher() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_CIPHER_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
            goldenCipherLogger.info("Login attempt for user " + data);
        }
    }
}
