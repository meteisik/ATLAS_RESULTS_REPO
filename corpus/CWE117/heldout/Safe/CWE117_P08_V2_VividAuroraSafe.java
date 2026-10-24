import java.util.logging.Logger;

public class CWE117_P08_V2_VividAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleVividAurora() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("VIVID_AURORA_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VividAuroraSafeSink()).logVividAurora(dataArray);
    }
}

class CWE117_P08_V2_VividAuroraSafeSink {
    public void logVividAurora(String[] dataArray) {
        String data = dataArray[2];
        Logger vividAuroraLogger = Logger.getLogger("vividAurora.audit");
        vividAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
