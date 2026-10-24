import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonHelixSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleCrimsonHelix() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("CRIMSON_HELIX_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonHelixSafeBase baseObject = new CWE117_P12_V2_CrimsonHelixSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonHelixSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonHelixSafeSink extends CWE117_P12_V2_CrimsonHelixSafeBase {
    public void action(String data) {
        Logger crimsonHelixLogger = Logger.getLogger("crimsonHelix.audit");
        crimsonHelixLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
