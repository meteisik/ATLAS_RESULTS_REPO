import java.util.logging.Logger;

public class CWE117_P12_V2_AzureAurora {
    private static boolean privateReturnsTrue() { return true; }

    public void handleAzureAurora() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_AURORA_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureAuroraBase baseObject = new CWE117_P12_V2_AzureAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureAuroraBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureAuroraSink extends CWE117_P12_V2_AzureAuroraBase {
    public void action(String data) {
        Logger azureAuroraLogger = Logger.getLogger("azureAurora.audit");
        azureAuroraLogger.info("Login attempt for user " + data);
    }
}
