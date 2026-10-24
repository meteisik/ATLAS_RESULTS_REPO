import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetCipherSafe {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void handleVelvetCipher() {
        String data;
        if (privateTrue) {
            data = System.getenv("VELVET_CIPHER_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetCipherSafeSink()).logVelvetCipher(dataContainer);
    }
}

class CWE117_P09_V2_VelvetCipherSafeSink {
    public void logVelvetCipher(CWE117_P09_V2_VelvetCipherSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
