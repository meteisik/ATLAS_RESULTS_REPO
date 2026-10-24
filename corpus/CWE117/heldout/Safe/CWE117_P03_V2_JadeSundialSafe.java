import java.util.logging.Logger;

public class CWE117_P03_V2_JadeSundialSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logJadeSundial(String data) {
        Logger jadeSundialLogger = Logger.getLogger("jadeSundial.audit");
        jadeSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeSundial() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("JADE_SUNDIAL_USER");
        } else {
            data = null;
        }
        logJadeSundial(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
