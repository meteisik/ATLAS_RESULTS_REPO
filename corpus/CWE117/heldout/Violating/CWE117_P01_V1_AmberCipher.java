import java.util.logging.Logger;

public class CWE117_P01_V1_AmberCipher {

    public void handleAmberCipher() {
        String data;
        data = System.getenv("AMBER_CIPHER_USER");
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + data);
    }
}
