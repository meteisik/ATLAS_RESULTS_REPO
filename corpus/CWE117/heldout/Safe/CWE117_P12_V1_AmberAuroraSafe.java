import java.util.logging.Logger;

public class CWE117_P12_V1_AmberAuroraSafe {

    public void handleAmberAurora() {
        String data;
        data = System.getenv("AMBER_AURORA_USER");
        CWE117_P12_V1_AmberAuroraSafeBase baseObject = new CWE117_P12_V1_AmberAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberAuroraSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberAuroraSafeSink extends CWE117_P12_V1_AmberAuroraSafeBase {
    public void action(String data) {
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
