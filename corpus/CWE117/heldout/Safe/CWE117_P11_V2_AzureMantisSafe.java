import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAzureMantis() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("AZURE_MANTIS_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AzureMantisSafeSink()).logAzureMantis(dataHashMap);
    }
}

class CWE117_P11_V2_AzureMantisSafeSink {
    public void logAzureMantis(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureMantisLogger = Logger.getLogger("azureMantis.audit");
        azureMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
