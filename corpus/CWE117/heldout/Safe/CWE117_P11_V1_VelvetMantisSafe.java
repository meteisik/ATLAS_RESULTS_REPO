import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetMantisSafe {

    public void handleVelvetMantis() {
        String data;
        data = System.getenv("VELVET_MANTIS_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetMantisSafeSink()).logVelvetMantis(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetMantisSafeSink {
    public void logVelvetMantis(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
