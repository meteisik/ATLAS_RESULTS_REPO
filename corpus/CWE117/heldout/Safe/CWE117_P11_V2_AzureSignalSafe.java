import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureSignalSafe {

    public void handleAzureSignal() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AZURE_SIGNAL_USER");
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE117_P11_V2_AzureSignalSafeSink()).logAzureSignal(dataHashMap);
    }
}

class CWE117_P11_V2_AzureSignalSafeSink {
    public void logAzureSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
