import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetAuroraSafe {

    public static String data;

    public void handleVelvetAurora() {
        data = System.getenv("VELVET_AURORA_USER");
        (new CWE117_P10_V1_VelvetAuroraSafeSink()).logVelvetAurora();
    }
}

class CWE117_P10_V1_VelvetAuroraSafeSink {
    public void logVelvetAurora() {
        String data = CWE117_P10_V1_VelvetAuroraSafe.data;
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
