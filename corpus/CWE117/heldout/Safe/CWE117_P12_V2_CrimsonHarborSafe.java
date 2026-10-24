import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonHarborSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleCrimsonHarbor() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("CRIMSON_HARBOR_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonHarborSafeBase baseObject = new CWE117_P12_V2_CrimsonHarborSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonHarborSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonHarborSafeSink extends CWE117_P12_V2_CrimsonHarborSafeBase {
    public void action(String data) {
        Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
        crimsonHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
