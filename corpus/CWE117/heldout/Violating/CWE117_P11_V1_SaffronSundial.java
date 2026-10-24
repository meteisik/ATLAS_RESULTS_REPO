import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SaffronSundial {

    public void handleSaffronSundial() {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SaffronSundialSink()).logSaffronSundial(dataHashMap);
    }
}

class CWE117_P11_V1_SaffronSundialSink {
    public void logSaffronSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + data);
    }
}
