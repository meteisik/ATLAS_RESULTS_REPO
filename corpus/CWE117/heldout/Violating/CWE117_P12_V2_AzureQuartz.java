import java.util.logging.Logger;

public class CWE117_P12_V2_AzureQuartz {

    public void handleAzureQuartz() {
        String data;
        while (true) {
            data = System.getenv("AZURE_QUARTZ_USER");
            break;
        }
        CWE117_P12_V2_AzureQuartzBase baseObject = new CWE117_P12_V2_AzureQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureQuartzBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureQuartzSink extends CWE117_P12_V2_AzureQuartzBase {
    public void action(String data) {
        Logger azureQuartzLogger = Logger.getLogger("azureQuartz.audit");
        azureQuartzLogger.info("Login attempt for user " + data);
    }
}
