import java.util.logging.Logger;

public class CWE117_P04_V1_JadeSundialSafe {

    private String readJadeSundial() {
        String data;
        data = System.getenv("JADE_SUNDIAL_USER");
        return data;
    }

    public void handleJadeSundial() {
        String data = readJadeSundial();
        Logger jadeSundialLogger = Logger.getLogger("jadeSundial.audit");
        jadeSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
