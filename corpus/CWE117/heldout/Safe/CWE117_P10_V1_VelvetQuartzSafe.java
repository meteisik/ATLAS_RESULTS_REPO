import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetQuartzSafe {

    public static String data;

    public void handleVelvetQuartz() {
        data = System.getenv("VELVET_QUARTZ_USER");
        (new CWE117_P10_V1_VelvetQuartzSafeSink()).logVelvetQuartz();
    }
}

class CWE117_P10_V1_VelvetQuartzSafeSink {
    public void logVelvetQuartz() {
        String data = CWE117_P10_V1_VelvetQuartzSafe.data;
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
