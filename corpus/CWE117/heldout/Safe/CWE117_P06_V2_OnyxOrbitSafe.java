import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleOnyxOrbit() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("ONYX_ORBIT_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxOrbitSafeSink()).logOnyxOrbit(data);
    }
}

class CWE117_P06_V2_OnyxOrbitSafeSink {
    public void logOnyxOrbit(String data) {
        Logger onyxOrbitLogger = Logger.getLogger("onyxOrbit.audit");
        onyxOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
