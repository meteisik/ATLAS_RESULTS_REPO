import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetCascadeSafe {

    public static String data;

    public void handleVelvetCascade() {
        data = System.getenv("VELVET_CASCADE_USER");
        (new CWE117_P10_V1_VelvetCascadeSafeSink()).logVelvetCascade();
    }
}

class CWE117_P10_V1_VelvetCascadeSafeSink {
    public void logVelvetCascade() {
        String data = CWE117_P10_V1_VelvetCascadeSafe.data;
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
