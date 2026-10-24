import java.util.logging.Logger;

public class CWE117_P12_V2_AzureSundial {

    public void handleAzureSundial() {
        String data;
        if (true) {
            data = System.getenv("AZURE_SUNDIAL_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureSundialBase baseObject = new CWE117_P12_V2_AzureSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureSundialBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureSundialSink extends CWE117_P12_V2_AzureSundialBase {
    public void action(String data) {
        Logger azureSundialLogger = Logger.getLogger("azureSundial.audit");
        azureSundialLogger.info("Login attempt for user " + data);
    }
}
