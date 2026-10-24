import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VividSundial {

    public void handleVividSundial() {
        String data;
        data = System.getenv("VIVID_SUNDIAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VividSundialSink()).logVividSundial(dataHashMap);
    }
}

class CWE117_P11_V1_VividSundialSink {
    public void logVividSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + data);
    }
}
