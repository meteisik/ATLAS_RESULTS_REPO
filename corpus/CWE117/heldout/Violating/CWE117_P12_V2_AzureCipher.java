import java.util.logging.Logger;

public class CWE117_P12_V2_AzureCipher {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleAzureCipher() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("AZURE_CIPHER_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_AzureCipherBase baseObject = new CWE117_P12_V2_AzureCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_AzureCipherBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_AzureCipherSink extends CWE117_P12_V2_AzureCipherBase {
    public void action(String data) {
        Logger azureCipherLogger = Logger.getLogger("azureCipher.audit");
        azureCipherLogger.info("Login attempt for user " + data);
    }
}
