import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleIvoryOrbit() {
        String dataCopy;
        {
            String data;
            if (IO.staticFive == 5) {
                data = System.getenv("IVORY_ORBIT_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryOrbitLogger = Logger.getLogger("ivoryOrbit.audit");
            ivoryOrbitLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
