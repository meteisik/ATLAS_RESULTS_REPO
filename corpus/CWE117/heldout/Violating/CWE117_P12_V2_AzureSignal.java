import java.util.logging.Logger;

public class CWE117_P12_V2_AzureSignal {

    public void handleAzureSignal() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AZURE_SIGNAL_USER");
        }
        CWE117_P12_V2_AzureSignalBase baseObject = new CWE117_P12_V2_AzureSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureSignalBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureSignalSink extends CWE117_P12_V2_AzureSignalBase {
    public void action(String data) {
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + data);
    }
}
