import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetCascadeSafe {

    public void handleVelvetCascade() {
        String data;
        data = System.getenv("VELVET_CASCADE_USER");
        CWE117_P12_V1_VelvetCascadeSafeBase baseObject = new CWE117_P12_V1_VelvetCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetCascadeSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetCascadeSafeSink extends CWE117_P12_V1_VelvetCascadeSafeBase {
    public void action(String data) {
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
