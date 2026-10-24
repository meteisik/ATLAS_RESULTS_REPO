import java.util.logging.Logger;

public class CWE117_P06_V2_RuneBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleRuneBeacon() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("RUNE_BEACON_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_RuneBeaconSink()).logRuneBeacon(data);
    }
}

class CWE117_P06_V2_RuneBeaconSink {
    public void logRuneBeacon(String data) {
        Logger runeBeaconLogger = Logger.getLogger("runeBeacon.audit");
        runeBeaconLogger.info("Login attempt for user " + data);
    }
}
