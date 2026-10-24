import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetAuroraSafe {

    public void handleVelvetAurora() {
        String data;
        data = System.getenv("VELVET_AURORA_USER");
        CWE117_P12_V1_VelvetAuroraSafeBase baseObject = new CWE117_P12_V1_VelvetAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetAuroraSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetAuroraSafeSink extends CWE117_P12_V1_VelvetAuroraSafeBase {
    public void action(String data) {
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
