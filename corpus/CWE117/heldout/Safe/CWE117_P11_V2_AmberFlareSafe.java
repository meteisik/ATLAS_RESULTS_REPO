import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberFlareSafe {
    private static boolean privateTrue = true;

    public void handleAmberFlare() {
        String data;
        if (privateTrue) {
            data = System.getenv("AMBER_FLARE_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberFlareSafeSink()).logAmberFlare(dataHashMap);
    }
}

class CWE117_P11_V2_AmberFlareSafeSink {
    public void logAmberFlare(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberFlareLogger = Logger.getLogger("amberFlare.audit");
        amberFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
