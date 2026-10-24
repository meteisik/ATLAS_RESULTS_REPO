import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VividGlint {

    public void handleVividGlint() {
        String data;
        data = System.getenv("VIVID_GLINT_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VividGlintSink()).logVividGlint(dataHashMap);
    }
}

class CWE117_P11_V1_VividGlintSink {
    public void logVividGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + data);
    }
}
