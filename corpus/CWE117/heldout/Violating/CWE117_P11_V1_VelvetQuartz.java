import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_VelvetQuartz {

    public void handleVelvetQuartz() {
        String data;
        data = System.getenv("VELVET_QUARTZ_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_VelvetQuartzSink()).logVelvetQuartz(dataHashMap);
    }
}

class CWE117_P11_V1_VelvetQuartzSink {
    public void logVelvetQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + data);
    }
}
