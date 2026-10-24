import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetSundial {

    public void handleVelvetSundial() {
        String data;
        data = System.getenv("VELVET_SUNDIAL_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetSundialSink()).logVelvetSundial(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetSundialSink {
    public void logVelvetSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + data);
    }
}
