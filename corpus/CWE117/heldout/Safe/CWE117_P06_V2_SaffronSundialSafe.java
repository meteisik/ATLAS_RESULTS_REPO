import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronSundialSafe {

    public void handleSaffronSundial() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("SAFFRON_SUNDIAL_USER");
        }
        (new CWE117_P06_V2_SaffronSundialSafeSink()).logSaffronSundial(data);
    }
}

class CWE117_P06_V2_SaffronSundialSafeSink {
    public void logSaffronSundial(String data) {
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
