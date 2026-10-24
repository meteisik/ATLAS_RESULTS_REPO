import java.util.logging.Logger;

public class CWE117_P06_V1_JadeSundialSafe {

    public void handleJadeSundial() {
        String data;
        data = System.getenv("JADE_SUNDIAL_USER");
        (new CWE117_P06_V1_JadeSundialSafeSink()).logJadeSundial(data);
    }
}

class CWE117_P06_V1_JadeSundialSafeSink {
    public void logJadeSundial(String data) {
        Logger jadeSundialLogger = Logger.getLogger("jadeSundial.audit");
        jadeSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
