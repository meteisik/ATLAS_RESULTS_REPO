import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_ArcticOrbit {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleArcticOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_ORBIT_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_ArcticOrbitSink()).logArcticOrbit(dataHashMap);
    }
}

class CWE117_P11_V2_ArcticOrbitSink {
    public void logArcticOrbit(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
        arcticOrbitLogger.info("Login attempt for user " + data);
    }
}
