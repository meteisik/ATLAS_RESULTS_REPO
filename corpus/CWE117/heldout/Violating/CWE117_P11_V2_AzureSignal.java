import java.util.HashMap;
import java.util.logging.Logger;

public class CWE117_P11_V2_AzureSignal {

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
        (new CWE117_P11_V2_AzureSignalSink()).logAzureSignal(dataHashMap);
    }
}

class CWE117_P11_V2_AzureSignalSink {
    public void logAzureSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + data);
    }
}
