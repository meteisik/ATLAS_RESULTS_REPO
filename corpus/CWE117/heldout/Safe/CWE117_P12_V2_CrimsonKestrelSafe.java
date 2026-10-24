import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonKestrelSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleCrimsonKestrel() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_KESTREL_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonKestrelSafeBase baseObject = new CWE117_P12_V2_CrimsonKestrelSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonKestrelSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonKestrelSafeSink extends CWE117_P12_V2_CrimsonKestrelSafeBase {
    public void action(String data) {
        Logger crimsonKestrelLogger = Logger.getLogger("crimsonKestrel.audit");
        crimsonKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
