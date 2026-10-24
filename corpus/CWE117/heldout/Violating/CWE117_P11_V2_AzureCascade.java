import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureCascade {
    private static int privateFive = 5;

    public void handleAzureCascade() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("AZURE_CASCADE_USER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AzureCascadeSink()).logAzureCascade(dataHashMap);
    }
}

class CWE117_P11_V2_AzureCascadeSink {
    public void logAzureCascade(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureCascadeLogger = Logger.getLogger("azureCascade.audit");
        azureCascadeLogger.info("Login attempt for user " + data);
    }
}
