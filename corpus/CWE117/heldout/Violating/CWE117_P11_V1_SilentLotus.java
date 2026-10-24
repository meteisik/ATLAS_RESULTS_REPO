import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentLotus {

    public void handleSilentLotus() {
        String data;
        data = System.getenv("SILENT_LOTUS_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentLotusSink()).logSilentLotus(dataHashMap);
    }
}

class CWE117_P11_V1_SilentLotusSink {
    public void logSilentLotus(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + data);
    }
}
