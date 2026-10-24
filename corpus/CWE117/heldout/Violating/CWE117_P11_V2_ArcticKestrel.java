import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticKestrel {

    public void handleArcticKestrel() {
        String data;
        while (true) {
            data = System.getenv("ARCTIC_KESTREL_USER");
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticKestrelSink()).logArcticKestrel(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticKestrelSink {
    public void logArcticKestrel(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticKestrelLogger = Logger.getLogger("arcticKestrel.audit");
        arcticKestrelLogger.info("Login attempt for user " + data);
    }
}
