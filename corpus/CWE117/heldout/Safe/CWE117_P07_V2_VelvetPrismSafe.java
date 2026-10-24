import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetPrismSafe {
    private static boolean privateTrue = true;

    public void handleVelvetPrism() {
        String data;
        if (privateTrue) {
            data = (new CWE117_P07_V2_VelvetPrismSafeSource()).readVelvetPrism();
        } else {
            data = null;
        }
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetPrismSafeSource {
    public String readVelvetPrism() {
        String data;
        data = System.getenv("VELVET_PRISM_USER");
        return data;
    }
}
