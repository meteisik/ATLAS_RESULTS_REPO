import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentRaven {

    public void handleSilentRaven() {
        String data;
        data = System.getenv("SILENT_RAVEN_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentRavenSink()).logSilentRaven(dataHashMap);
    }
}

class CWE117_P11_V1_SilentRavenSink {
    public void logSilentRaven(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + data);
    }
}
