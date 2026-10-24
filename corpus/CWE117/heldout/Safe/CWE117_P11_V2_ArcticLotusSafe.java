import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticLotusSafe {

    public void handleArcticLotus() {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_LOTUS_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticLotusSafeSink()).logArcticLotus(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticLotusSafeSink {
    public void logArcticLotus(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
        arcticLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
