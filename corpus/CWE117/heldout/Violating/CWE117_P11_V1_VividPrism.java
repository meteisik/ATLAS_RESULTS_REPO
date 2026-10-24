import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VividPrism {

    public void handleVividPrism() {
        String data;
        data = System.getenv("VIVID_PRISM_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VividPrismSink()).logVividPrism(dataHashMap);
    }
}

class CWE117_P11_V1_VividPrismSink {
    public void logVividPrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + data);
    }
}
