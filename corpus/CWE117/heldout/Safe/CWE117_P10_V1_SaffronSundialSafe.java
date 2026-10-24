import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronSundialSafe {

    public static String data;

    public void handleSaffronSundial() {
        data = System.getenv("SAFFRON_SUNDIAL_USER");
        (new CWE117_P10_V1_SaffronSundialSafeSink()).logSaffronSundial();
    }
}

class CWE117_P10_V1_SaffronSundialSafeSink {
    public void logSaffronSundial() {
        String data = CWE117_P10_V1_SaffronSundialSafe.data;
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
