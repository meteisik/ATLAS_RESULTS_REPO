import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticLantern {

    public void handleArcticLantern() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ARCTIC_LANTERN_USER");
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticLanternSink()).logArcticLantern(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticLanternSink {
    public void logArcticLantern(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticLanternLogger = Logger.getLogger("arcticLantern.audit");
        arcticLanternLogger.info("Login attempt for user " + data);
    }
}
