import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAzureGlint() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("AZURE_GLINT_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AzureGlintSink()).logAzureGlint(dataHashMap);
    }
}

class CWE117_P11_V2_AzureGlintSink {
    public void logAzureGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureGlintLogger = Logger.getLogger("azureGlint.audit");
        azureGlintLogger.info("Login attempt for user " + data);
    }
}
