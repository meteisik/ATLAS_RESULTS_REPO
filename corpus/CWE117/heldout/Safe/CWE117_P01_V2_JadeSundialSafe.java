import java.util.logging.Logger;

public class CWE117_P01_V2_JadeSundialSafe {
    private static int privateFive = 5;

    public void handleJadeSundial() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("JADE_SUNDIAL_USER");
        } else {
            data = null;
        }
        Logger jadeSundialLogger = Logger.getLogger("jadeSundial.audit");
        jadeSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
