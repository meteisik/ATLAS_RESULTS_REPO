import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetPrism {

    public void handleVelvetPrism() {
        String data;
        data = System.getenv("VELVET_PRISM_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetPrismSink()).logVelvetPrism(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetPrismSink {
    public void logVelvetPrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + data);
    }
}
