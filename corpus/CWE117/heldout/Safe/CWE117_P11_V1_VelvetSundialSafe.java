import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetSundialSafe {

    public void handleVelvetSundial() {
        String data;
        data = System.getenv("VELVET_SUNDIAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetSundialSafeSink()).logVelvetSundial(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetSundialSafeSink {
    public void logVelvetSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
