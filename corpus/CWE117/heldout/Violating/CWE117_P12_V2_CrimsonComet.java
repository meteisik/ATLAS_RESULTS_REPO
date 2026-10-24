import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonComet {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleCrimsonComet() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("CRIMSON_COMET_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonCometBase baseObject = new CWE117_P12_V2_CrimsonCometSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonCometBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonCometSink extends CWE117_P12_V2_CrimsonCometBase {
    public void action(String data) {
        Logger crimsonCometLogger = Logger.getLogger("crimsonComet.audit");
        crimsonCometLogger.info("Login attempt for user " + data);
    }
}
