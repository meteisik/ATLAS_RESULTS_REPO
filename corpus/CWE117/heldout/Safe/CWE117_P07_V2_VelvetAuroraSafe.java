import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetAuroraSafe {

    public void handleVelvetAurora() {
        String data;
        switch (7) {
        case 7:
            data = (new CWE117_P07_V2_VelvetAuroraSafeSource()).readVelvetAurora();
            break;
        default:
            data = null;
            break;
        }
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetAuroraSafeSource {
    public String readVelvetAurora() {
        String data;
        data = System.getenv("VELVET_AURORA_USER");
        return data;
    }
}
