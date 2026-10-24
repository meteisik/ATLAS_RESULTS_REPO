import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronSundial {

    public void handleSaffronSundial() {
        String data;
        if (5 == 5) {
            data = (new CWE117_P07_V2_SaffronSundialSource()).readSaffronSundial();
        } else {
            data = null;
        }
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SaffronSundialSource {
    public String readSaffronSundial() {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_USER");
        return data;
    }
}
