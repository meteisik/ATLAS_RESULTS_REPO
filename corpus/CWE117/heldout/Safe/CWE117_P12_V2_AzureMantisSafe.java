import java.util.logging.Logger;

public class CWE117_P12_V2_AzureMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAzureMantis() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("AZURE_MANTIS_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureMantisSafeBase baseObject = new CWE117_P12_V2_AzureMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureMantisSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureMantisSafeSink extends CWE117_P12_V2_AzureMantisSafeBase {
    public void action(String data) {
        Logger azureMantisLogger = Logger.getLogger("azureMantis.audit");
        azureMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
