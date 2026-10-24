import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetPrismSafe {

    public void handleVelvetPrism() {
        String data;
        data = System.getenv("VELVET_PRISM_USER");
        CWE117_P12_V1_VelvetPrismSafeBase baseObject = new CWE117_P12_V1_VelvetPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetPrismSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetPrismSafeSink extends CWE117_P12_V1_VelvetPrismSafeBase {
    public void action(String data) {
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
