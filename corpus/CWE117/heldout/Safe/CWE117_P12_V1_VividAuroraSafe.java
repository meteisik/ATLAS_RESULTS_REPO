import java.util.logging.Logger;

public class CWE117_P12_V1_VividAuroraSafe {

    public void handleVividAurora() {
        String data;
        data = System.getenv("VIVID_AURORA_USER");
        CWE117_P12_V1_VividAuroraSafeBase baseObject = new CWE117_P12_V1_VividAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividAuroraSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividAuroraSafeSink extends CWE117_P12_V1_VividAuroraSafeBase {
    public void action(String data) {
        Logger vividAuroraLogger = Logger.getLogger("vividAurora.audit");
        vividAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
