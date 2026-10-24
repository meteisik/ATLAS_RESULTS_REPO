import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VividSignal {

    public void handleVividSignal() {
        String data;
        data = System.getenv("VIVID_SIGNAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VividSignalSink()).logVividSignal(dataHashMap);
    }
}

class CWE117_P11_V1_VividSignalSink {
    public void logVividSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger vividSignalLogger = Logger.getLogger("vividSignal.audit");
        vividSignalLogger.info("Login attempt for user " + data);
    }
}
