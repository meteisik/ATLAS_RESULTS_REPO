import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetQuartzSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleVelvetQuartz() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE117_P07_V2_VelvetQuartzSafeSource()).readVelvetQuartz();
        } else {
            data = null;
        }
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetQuartzSafeSource {
    public String readVelvetQuartz() {
        String data;
        data = System.getenv("VELVET_QUARTZ_USER");
        return data;
    }
}
