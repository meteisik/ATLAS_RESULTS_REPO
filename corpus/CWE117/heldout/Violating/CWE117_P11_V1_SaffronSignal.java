import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SaffronSignal {

    public void handleSaffronSignal() {
        String data;
        data = System.getenv("SAFFRON_SIGNAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SaffronSignalSink()).logSaffronSignal(dataHashMap);
    }
}

class CWE117_P11_V1_SaffronSignalSink {
    public void logSaffronSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + data);
    }
}
