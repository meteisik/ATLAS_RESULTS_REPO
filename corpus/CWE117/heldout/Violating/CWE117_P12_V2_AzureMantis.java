import java.util.logging.Logger;

public class CWE117_P12_V2_AzureMantis {
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
        CWE117_P12_V2_AzureMantisBase baseObject = new CWE117_P12_V2_AzureMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureMantisBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureMantisSink extends CWE117_P12_V2_AzureMantisBase {
    public void action(String data) {
        Logger azureMantisLogger = Logger.getLogger("azureMantis.audit");
        azureMantisLogger.info("Login attempt for user " + data);
    }
}
