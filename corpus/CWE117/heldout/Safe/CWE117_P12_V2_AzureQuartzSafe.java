import java.util.logging.Logger;

public class CWE117_P12_V2_AzureQuartzSafe {

    public void handleAzureQuartz() {
        String data;
        while (true) {
            data = System.getenv("AZURE_QUARTZ_USER");
            break;
        }
        CWE117_P12_V2_AzureQuartzSafeBase baseObject = new CWE117_P12_V2_AzureQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureQuartzSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureQuartzSafeSink extends CWE117_P12_V2_AzureQuartzSafeBase {
    public void action(String data) {
        Logger azureQuartzLogger = Logger.getLogger("azureQuartz.audit");
        azureQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
