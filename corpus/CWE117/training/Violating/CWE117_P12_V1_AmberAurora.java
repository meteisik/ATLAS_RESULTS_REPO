import java.util.logging.Logger;

public class CWE117_P12_V1_AmberAurora {

    public void handleAmberAurora() {
        String data;
        data = System.getenv("AMBER_AURORA_USER");
        CWE117_P12_V1_AmberAuroraBase baseObject = new CWE117_P12_V1_AmberAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberAuroraBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberAuroraSink extends CWE117_P12_V1_AmberAuroraBase {
    public void action(String data) {
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + data);
    }
}
