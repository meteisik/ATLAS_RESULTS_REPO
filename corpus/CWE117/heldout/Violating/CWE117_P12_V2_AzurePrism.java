import java.util.logging.Logger;

public class CWE117_P12_V2_AzurePrism {

    public void handleAzurePrism() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AZURE_PRISM_USER");
            break;
        default:
            data = null;
            break;
        }
        CWE117_P12_V2_AzurePrismBase baseObject = new CWE117_P12_V2_AzurePrismSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzurePrismBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzurePrismSink extends CWE117_P12_V2_AzurePrismBase {
    public void action(String data) {
        Logger azurePrismLogger = Logger.getLogger("azurePrism.audit");
        azurePrismLogger.info("Login attempt for user " + data);
    }
}
