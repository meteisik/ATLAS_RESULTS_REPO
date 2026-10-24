import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetAurora {

    public static String data;

    public void handleVelvetAurora() {
        data = System.getenv("VELVET_AURORA_USER");
        (new CWE117_P10_V1_VelvetAuroraSink()).logVelvetAurora();
    }
}

class CWE117_P10_V1_VelvetAuroraSink {
    public void logVelvetAurora() {
        String data = CWE117_P10_V1_VelvetAurora.data;
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + data);
    }
}
