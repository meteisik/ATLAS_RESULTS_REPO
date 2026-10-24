import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticNebulaSafe {

    public void handleArcticNebula() {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_NEBULA_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticNebulaSafeSink()).logArcticNebula(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticNebulaSafeSink {
    public void logArcticNebula(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticNebulaLogger = Logger.getLogger("arcticNebula.audit");
        arcticNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
