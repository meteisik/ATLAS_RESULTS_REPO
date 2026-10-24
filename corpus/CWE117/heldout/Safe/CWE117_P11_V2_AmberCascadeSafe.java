import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberCascadeSafe {

    public void handleAmberCascade() {
        String data;
        if (5 == 5) {
            data = System.getenv("AMBER_CASCADE_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberCascadeSafeSink()).logAmberCascade(dataHashMap);
    }
}

class CWE117_P11_V2_AmberCascadeSafeSink {
    public void logAmberCascade(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
