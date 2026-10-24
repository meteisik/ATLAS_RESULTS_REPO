import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenAuroraSafe {

    public void handleGoldenAurora() {
        String data;
        if (5 == 5) {
            data = System.getenv("GOLDEN_AURORA_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenAuroraSafeBase baseObject = new CWE117_P12_V2_GoldenAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenAuroraSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenAuroraSafeSink extends CWE117_P12_V2_GoldenAuroraSafeBase {
    public void action(String data) {
        Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
        goldenAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
