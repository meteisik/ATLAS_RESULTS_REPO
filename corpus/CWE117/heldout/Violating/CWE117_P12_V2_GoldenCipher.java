import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenCipher {
    private static boolean privateTrue = true;

    public void handleGoldenCipher() {
        String data;
        if (privateTrue) {
            data = System.getenv("GOLDEN_CIPHER_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenCipherBase baseObject = new CWE117_P12_V2_GoldenCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenCipherBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenCipherSink extends CWE117_P12_V2_GoldenCipherBase {
    public void action(String data) {
        Logger goldenCipherLogger = Logger.getLogger("goldenCipher.audit");
        goldenCipherLogger.info("Login attempt for user " + data);
    }
}
