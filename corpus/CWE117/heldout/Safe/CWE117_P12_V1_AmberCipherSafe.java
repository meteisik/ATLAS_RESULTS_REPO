import java.util.logging.Logger;

public class CWE117_P12_V1_AmberCipherSafe {

    public void handleAmberCipher() {
        String data;
        data = System.getenv("AMBER_CIPHER_USER");
        CWE117_P12_V1_AmberCipherSafeBase baseObject = new CWE117_P12_V1_AmberCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberCipherSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberCipherSafeSink extends CWE117_P12_V1_AmberCipherSafeBase {
    public void action(String data) {
        Logger amberCipherLogger = Logger.getLogger("amberCipher.audit");
        amberCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
