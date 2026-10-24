import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AmberMantis {
    private static int privateFive = 5;

    public void handleAmberMantis() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("AMBER_MANTIS_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AmberMantisSink()).logAmberMantis(dataHashMap);
    }
}

class CWE117_P11_V2_AmberMantisSink {
    public void logAmberMantis(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + data);
    }
}
