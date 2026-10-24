import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrAuroraSafe {

    public void handleZephyrAurora() {
        String data;
        data = System.getenv("ZEPHYR_AURORA_USER");
        CWE117_P12_V1_ZephyrAuroraSafeBase baseObject = new CWE117_P12_V1_ZephyrAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrAuroraSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrAuroraSafeSink extends CWE117_P12_V1_ZephyrAuroraSafeBase {
    public void action(String data) {
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
