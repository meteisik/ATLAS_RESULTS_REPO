import java.util.logging.Logger;

public class CWE117_P12_V1_VividAurora {

    public void handleVividAurora() {
        String data;
        data = System.getenv("VIVID_AURORA_USER");
        CWE117_P12_V1_VividAuroraBase baseObject = new CWE117_P12_V1_VividAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividAuroraBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividAuroraSink extends CWE117_P12_V1_VividAuroraBase {
    public void action(String data) {
        Logger vividAuroraLogger = Logger.getLogger("vividAurora.audit");
        vividAuroraLogger.info("Login attempt for user " + data);
    }
}
