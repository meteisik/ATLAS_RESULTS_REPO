import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronSundialSafe {

    public void handleSaffronSundial() {
        String data;
        if (5 == 5) {
            data = (new CWE117_P07_V2_SaffronSundialSafeSource()).readSaffronSundial();
        } else {
            data = null;
        }
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SaffronSundialSafeSource {
    public String readSaffronSundial() {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_USER");
        return data;
    }
}
