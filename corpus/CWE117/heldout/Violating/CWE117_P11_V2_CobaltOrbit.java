import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_CobaltOrbit {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleCobaltOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_ORBIT_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_CobaltOrbitSink()).logCobaltOrbit(dataHashMap);
    }
}

class CWE117_P11_V2_CobaltOrbitSink {
    public void logCobaltOrbit(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger cobaltOrbitLogger = Logger.getLogger("cobaltOrbit.audit");
        cobaltOrbitLogger.info("Login attempt for user " + data);
    }
}
