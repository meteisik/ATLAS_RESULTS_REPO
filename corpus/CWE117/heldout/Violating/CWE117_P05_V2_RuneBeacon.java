import java.util.logging.Logger;

public class CWE117_P05_V2_RuneBeacon {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeBeaconData;

    private void logRuneBeacon() {
        String data = runeBeaconData;
        Logger runeBeaconLogger = Logger.getLogger("runeBeacon.audit");
        runeBeaconLogger.info("Login attempt for user " + data);
    }

    public void handleRuneBeacon() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("RUNE_BEACON_USER");
        } else {
            data = null;
        }
        runeBeaconData = data;
        logRuneBeacon();
    }
}
