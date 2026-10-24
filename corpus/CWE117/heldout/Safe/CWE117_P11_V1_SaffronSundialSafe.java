import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SaffronSundialSafe {

    public void handleSaffronSundial() {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SaffronSundialSafeSink()).logSaffronSundial(dataHashMap);
    }
}

class CWE117_P11_V1_SaffronSundialSafeSink {
    public void logSaffronSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
