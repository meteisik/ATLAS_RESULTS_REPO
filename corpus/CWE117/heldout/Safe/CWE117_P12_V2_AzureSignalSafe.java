import java.util.logging.Logger;

public class CWE117_P12_V2_AzureSignalSafe {

    public void handleAzureSignal() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AZURE_SIGNAL_USER");
        }
        CWE117_P12_V2_AzureSignalSafeBase baseObject = new CWE117_P12_V2_AzureSignalSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureSignalSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureSignalSafeSink extends CWE117_P12_V2_AzureSignalSafeBase {
    public void action(String data) {
        Logger azureSignalLogger = Logger.getLogger("azureSignal.audit");
        azureSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
