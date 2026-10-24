import java.util.logging.Logger;

public class CWE117_P12_V2_AzureSundialSafe {

    public void handleAzureSundial() {
        String data;
        if (true) {
            data = System.getenv("AZURE_SUNDIAL_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureSundialSafeBase baseObject = new CWE117_P12_V2_AzureSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureSundialSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureSundialSafeSink extends CWE117_P12_V2_AzureSundialSafeBase {
    public void action(String data) {
        Logger azureSundialLogger = Logger.getLogger("azureSundial.audit");
        azureSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
