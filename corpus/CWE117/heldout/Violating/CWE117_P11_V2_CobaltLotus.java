import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CobaltLotus {

    public void handleCobaltLotus() {
        String data;
        if (5 == 5) {
            data = System.getenv("COBALT_LOTUS_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CobaltLotusSink()).logCobaltLotus(dataHashMap);
    }
}

class CWE117_P11_V2_CobaltLotusSink {
    public void logCobaltLotus(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger cobaltLotusLogger = Logger.getLogger("cobaltLotus.audit");
        cobaltLotusLogger.info("Login attempt for user " + data);
    }
}
