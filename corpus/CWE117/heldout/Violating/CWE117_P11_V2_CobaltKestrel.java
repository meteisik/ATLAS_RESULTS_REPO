import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CobaltKestrel {

    public void handleCobaltKestrel() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("COBALT_KESTREL_USER");
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CobaltKestrelSink()).logCobaltKestrel(dataHashMap);
    }
}

class CWE117_P11_V2_CobaltKestrelSink {
    public void logCobaltKestrel(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger cobaltKestrelLogger = Logger.getLogger("cobaltKestrel.audit");
        cobaltKestrelLogger.info("Login attempt for user " + data);
    }
}
