import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetAurora {

    public void handleVelvetAurora() {
        String data;
        data = System.getenv("VELVET_AURORA_USER");
        CWE117_P12_V1_VelvetAuroraBase baseObject = new CWE117_P12_V1_VelvetAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetAuroraBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetAuroraSink extends CWE117_P12_V1_VelvetAuroraBase {
    public void action(String data) {
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + data);
    }
}
