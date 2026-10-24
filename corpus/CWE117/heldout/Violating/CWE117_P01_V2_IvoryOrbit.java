import java.util.logging.Logger;

public class CWE117_P01_V2_IvoryOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleIvoryOrbit() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("IVORY_ORBIT_USER");
        } else {
            data = null;
        }
        Logger ivoryOrbitLogger = Logger.getLogger("ivoryOrbit.audit");
        ivoryOrbitLogger.info("Login attempt for user " + data);
    }
}
