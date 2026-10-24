import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronSundial {

    public static String data;

    public void handleSaffronSundial() {
        data = System.getenv("SAFFRON_SUNDIAL_USER");
        (new CWE117_P10_V1_SaffronSundialSink()).logSaffronSundial();
    }
}

class CWE117_P10_V1_SaffronSundialSink {
    public void logSaffronSundial() {
        String data = CWE117_P10_V1_SaffronSundial.data;
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + data);
    }
}
