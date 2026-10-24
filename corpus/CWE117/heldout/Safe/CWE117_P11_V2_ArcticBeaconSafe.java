import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticBeaconSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleArcticBeacon() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ARCTIC_BEACON_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticBeaconSafeSink()).logArcticBeacon(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticBeaconSafeSink {
    public void logArcticBeacon(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticBeaconLogger = Logger.getLogger("arcticBeacon.audit");
        arcticBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
