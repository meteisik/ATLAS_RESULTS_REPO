import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxLotusSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleOnyxLotus() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_LOTUS_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxLotusSafeSink()).logOnyxLotus(data);
    }
}

class CWE117_P06_V2_OnyxLotusSafeSink {
    public void logOnyxLotus(String data) {
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
