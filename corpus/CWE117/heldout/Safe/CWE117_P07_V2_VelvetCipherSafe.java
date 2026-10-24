import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetCipherSafe {

    public void handleVelvetCipher() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = (new CWE117_P07_V2_VelvetCipherSafeSource()).readVelvetCipher();
        }
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetCipherSafeSource {
    public String readVelvetCipher() {
        String data;
        data = System.getenv("VELVET_CIPHER_USER");
        return data;
    }
}
