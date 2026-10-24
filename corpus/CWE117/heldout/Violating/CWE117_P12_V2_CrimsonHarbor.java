import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonHarbor {
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
        CWE117_P12_V2_CrimsonHarborBase baseObject = new CWE117_P12_V2_CrimsonHarborSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonHarborBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonHarborSink extends CWE117_P12_V2_CrimsonHarborBase {
    public void action(String data) {
        Logger crimsonHarborLogger = Logger.getLogger("crimsonHarbor.audit");
        crimsonHarborLogger.info("Login attempt for user " + data);
    }
}
