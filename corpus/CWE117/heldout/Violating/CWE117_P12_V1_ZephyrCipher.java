import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrCipher {

    public void handleZephyrCipher() {
        String data;
        data = System.getenv("ZEPHYR_CIPHER_USER");
        CWE117_P12_V1_ZephyrCipherBase baseObject = new CWE117_P12_V1_ZephyrCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrCipherBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrCipherSink extends CWE117_P12_V1_ZephyrCipherBase {
    public void action(String data) {
        Logger zephyrCipherLogger = Logger.getLogger("zephyrCipher.audit");
        zephyrCipherLogger.info("Login attempt for user " + data);
    }
}
