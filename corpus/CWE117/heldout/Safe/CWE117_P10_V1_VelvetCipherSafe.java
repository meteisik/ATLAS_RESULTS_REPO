import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetCipherSafe {

    public static String data;

    public void handleVelvetCipher() {
        data = System.getenv("VELVET_CIPHER_USER");
        (new CWE117_P10_V1_VelvetCipherSafeSink()).logVelvetCipher();
    }
}

class CWE117_P10_V1_VelvetCipherSafeSink {
    public void logVelvetCipher() {
        String data = CWE117_P10_V1_VelvetCipherSafe.data;
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
