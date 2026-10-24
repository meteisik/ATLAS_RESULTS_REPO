import java.util.logging.Logger;

public class CWE117_P12_V2_AzureAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleAzureAurora() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_AURORA_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureAuroraSafeBase baseObject = new CWE117_P12_V2_AzureAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureAuroraSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureAuroraSafeSink extends CWE117_P12_V2_AzureAuroraSafeBase {
    public void action(String data) {
        Logger azureAuroraLogger = Logger.getLogger("azureAurora.audit");
        azureAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
