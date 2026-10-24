import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetCipherSafe {

    public void handleVelvetCipher() {
        String data;
        data = System.getenv("VELVET_CIPHER_USER");
        CWE117_P12_V1_VelvetCipherSafeBase baseObject = new CWE117_P12_V1_VelvetCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetCipherSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetCipherSafeSink extends CWE117_P12_V1_VelvetCipherSafeBase {
    public void action(String data) {
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
