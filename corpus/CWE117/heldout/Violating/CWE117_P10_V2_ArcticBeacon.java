import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void handleArcticBeacon() {
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_BEACON_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticBeaconSink()).logArcticBeacon();
    }
}

class CWE117_P10_V2_ArcticBeaconSink {
    public void logArcticBeacon() {
        String data = CWE117_P10_V2_ArcticBeacon.data;
        Logger arcticBeaconLogger = Logger.getLogger("arcticBeacon.audit");
        arcticBeaconLogger.info("Login attempt for user " + data);
    }
}
