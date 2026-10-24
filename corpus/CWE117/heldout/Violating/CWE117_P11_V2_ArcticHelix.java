import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticHelix {

    public void handleArcticHelix() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("ARCTIC_HELIX_USER");
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticHelixSink()).logArcticHelix(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticHelixSink {
    public void logArcticHelix(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticHelixLogger = Logger.getLogger("arcticHelix.audit");
        arcticHelixLogger.info("Login attempt for user " + data);
    }
}
