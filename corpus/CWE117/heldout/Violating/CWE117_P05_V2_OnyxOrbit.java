import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String onyxOrbitData;

    private void logOnyxOrbit() {
        String data = onyxOrbitData;
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + data);
    }

    public void handleOnyxOrbit() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_ORBIT_USER");
        } else {
            data = null;
        }
        onyxOrbitData = data;
        logOnyxOrbit();
    }
}
