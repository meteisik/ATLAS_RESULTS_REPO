import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetPrismSafe {

    public static String data;

    public void handleVelvetPrism() {
        data = System.getenv("VELVET_PRISM_USER");
        (new CWE117_P10_V1_VelvetPrismSafeSink()).logVelvetPrism();
    }
}

class CWE117_P10_V1_VelvetPrismSafeSink {
    public void logVelvetPrism() {
        String data = CWE117_P10_V1_VelvetPrismSafe.data;
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
