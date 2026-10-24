import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V1_SilentOrbit {

    public void handleSilentOrbit() {
        String data;
        data = System.getenv("SILENT_ORBIT_USER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V1_SilentOrbitSink()).logSilentOrbit(dataHashMap);
    }
}

class CWE117_P11_V1_SilentOrbitSink {
    public void logSilentOrbit(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger silentOrbitLogger = Logger.getLogger("silentOrbit.audit");
        silentOrbitLogger.info("Login attempt for user " + data);
    }
}
