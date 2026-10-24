import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentKestrel {

    public void handleSilentKestrel() {
        String data;
        data = System.getenv("SILENT_KESTREL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentKestrelSink()).logSilentKestrel(dataHashMap);
    }
}

class CWE117_P11_V1_SilentKestrelSink {
    public void logSilentKestrel(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + data);
    }
}
