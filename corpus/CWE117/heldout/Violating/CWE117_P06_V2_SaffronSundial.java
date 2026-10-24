import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronSundial {

    public void handleSaffronSundial() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("SAFFRON_SUNDIAL_USER");
        }
        (new CWE117_P06_V2_SaffronSundialSink()).logSaffronSundial(data);
    }
}

class CWE117_P06_V2_SaffronSundialSink {
    public void logSaffronSundial(String data) {
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + data);
    }
}
