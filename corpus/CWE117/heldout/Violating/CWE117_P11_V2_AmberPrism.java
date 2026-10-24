import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberPrism {
    private static boolean privateReturnsTrue() { return true; }

    public void handleAmberPrism() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AMBER_PRISM_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberPrismSink()).logAmberPrism(dataHashMap);
    }
}

class CWE117_P11_V2_AmberPrismSink {
    public void logAmberPrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + data);
    }
}
