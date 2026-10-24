import java.util.logging.Logger;

public class CWE117_P12_V2_AzurePrismSafe {

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
        CWE117_P12_V2_AzurePrismSafeBase baseObject = new CWE117_P12_V2_AzurePrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzurePrismSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzurePrismSafeSink extends CWE117_P12_V2_AzurePrismSafeBase {
    public void action(String data) {
        Logger azurePrismLogger = Logger.getLogger("azurePrism.audit");
        azurePrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
