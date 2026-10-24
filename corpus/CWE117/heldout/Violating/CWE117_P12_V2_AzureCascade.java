import java.util.logging.Logger;

public class CWE117_P12_V2_AzureCascade {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAzureCascade() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("AZURE_CASCADE_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureCascadeBase baseObject = new CWE117_P12_V2_AzureCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureCascadeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureCascadeSink extends CWE117_P12_V2_AzureCascadeBase {
    public void action(String data) {
        Logger azureCascadeLogger = Logger.getLogger("azureCascade.audit");
        azureCascadeLogger.info("Login attempt for user " + data);
    }
}
