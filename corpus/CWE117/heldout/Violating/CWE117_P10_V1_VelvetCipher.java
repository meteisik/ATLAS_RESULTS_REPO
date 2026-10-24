import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetCipher {

    public static String data;

    public void handleVelvetCipher() {
        data = System.getenv("VELVET_CIPHER_USER");
        (new CWE117_P10_V1_VelvetCipherSink()).logVelvetCipher();
    }
}

class CWE117_P10_V1_VelvetCipherSink {
    public void logVelvetCipher() {
        String data = CWE117_P10_V1_VelvetCipher.data;
        Logger velvetCipherLogger = Logger.getLogger("velvetCipher.audit");
        velvetCipherLogger.info("Login attempt for user " + data);
    }
}
