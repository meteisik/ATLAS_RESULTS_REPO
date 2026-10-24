import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenCipherSafe {
    private static boolean privateTrue = true;

    public void handleGoldenCipher() {
        String data;
        if (privateTrue) {
            data = System.getenv("GOLDEN_CIPHER_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenCipherSafeBase baseObject = new CWE117_P12_V2_GoldenCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenCipherSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenCipherSafeSink extends CWE117_P12_V2_GoldenCipherSafeBase {
    public void action(String data) {
        Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
        goldenCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
