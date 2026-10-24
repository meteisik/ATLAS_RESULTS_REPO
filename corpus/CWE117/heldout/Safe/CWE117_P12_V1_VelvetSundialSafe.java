import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetSundialSafe {

    public void handleVelvetSundial() {
        String data;
        data = System.getenv("VELVET_SUNDIAL_USER");
        CWE117_P12_V1_VelvetSundialSafeBase baseObject = new CWE117_P12_V1_VelvetSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetSundialSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetSundialSafeSink extends CWE117_P12_V1_VelvetSundialSafeBase {
    public void action(String data) {
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
