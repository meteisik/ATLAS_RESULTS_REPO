import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrCipherSafe {

    public void handleZephyrCipher() {
        String data;
        data = System.getenv("ZEPHYR_CIPHER_USER");
        CWE117_P12_V1_ZephyrCipherSafeBase baseObject = new CWE117_P12_V1_ZephyrCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrCipherSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrCipherSafeSink extends CWE117_P12_V1_ZephyrCipherSafeBase {
    public void action(String data) {
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
