import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonLantern {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleCrimsonLantern() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("CRIMSON_LANTERN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonLanternBase baseObject = new CWE117_P12_V2_CrimsonLanternSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonLanternBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonLanternSink extends CWE117_P12_V2_CrimsonLanternBase {
    public void action(String data) {
        Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
        crimsonLanternLogger.info("Login attempt for user " + data);
    }
}
