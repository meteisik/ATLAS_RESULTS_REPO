import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VividPrismSafe {

    public void handleVividPrism() {
        String data;
        data = System.getenv("VIVID_PRISM_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VividPrismSafeSink()).logVividPrism(dataHashMap);
    }
}

class CWE117_P11_V1_VividPrismSafeSink {
    public void logVividPrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
