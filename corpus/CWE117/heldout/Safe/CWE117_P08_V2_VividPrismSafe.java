import java.util.logging.Logger;

public class CWE117_P08_V2_VividPrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleVividPrism() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("VIVID_PRISM_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VividPrismSafeSink()).logVividPrism(dataArray);
    }
}

class CWE117_P08_V2_VividPrismSafeSink {
    public void logVividPrism(String[] dataArray) {
        String data = dataArray[2];
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
