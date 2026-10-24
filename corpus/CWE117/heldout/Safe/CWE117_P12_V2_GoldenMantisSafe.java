import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenMantisSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleGoldenMantis() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("GOLDEN_MANTIS_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenMantisSafeBase baseObject = new CWE117_P12_V2_GoldenMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenMantisSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenMantisSafeSink extends CWE117_P12_V2_GoldenMantisSafeBase {
    public void action(String data) {
        Logger goldenMantisLogger = Logger.getLogger("goldenMantis.audit");
        goldenMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
