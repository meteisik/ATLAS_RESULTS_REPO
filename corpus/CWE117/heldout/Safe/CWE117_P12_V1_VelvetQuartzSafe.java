import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetQuartzSafe {

    public void handleVelvetQuartz() {
        String data;
        data = System.getenv("VELVET_QUARTZ_USER");
        CWE117_P12_V1_VelvetQuartzSafeBase baseObject = new CWE117_P12_V1_VelvetQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetQuartzSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetQuartzSafeSink extends CWE117_P12_V1_VelvetQuartzSafeBase {
    public void action(String data) {
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
