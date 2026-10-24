import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAmberQuartz() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_QUARTZ_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberQuartzSafeSink()).logAmberQuartz(dataHashMap);
    }
}

class CWE117_P11_V2_AmberQuartzSafeSink {
    public void logAmberQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberQuartzLogger = Logger.getLogger("amberQuartz.audit");
        amberQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
