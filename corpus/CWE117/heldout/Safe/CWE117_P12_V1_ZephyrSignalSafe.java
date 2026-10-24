import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrSignalSafe {

    public void handleZephyrSignal() {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_USER");
        CWE117_P12_V1_ZephyrSignalSafeBase baseObject = new CWE117_P12_V1_ZephyrSignalSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrSignalSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrSignalSafeSink extends CWE117_P12_V1_ZephyrSignalSafeBase {
    public void action(String data) {
        Logger zephyrSignalLogger = Logger.getLogger("zephyrSignal.audit");
        zephyrSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
