import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronPrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSaffronPrism() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("SAFFRON_PRISM_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronPrismSink()).logSaffronPrism(data);
    }
}

class CWE117_P06_V2_SaffronPrismSink {
    public void logSaffronPrism(String data) {
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + data);
    }
}
