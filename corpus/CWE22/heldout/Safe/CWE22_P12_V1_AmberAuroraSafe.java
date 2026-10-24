import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberAuroraSafe {

    public void openAmberAurora() {
        String data;
        data = "foo";
        CWE22_P12_V1_AmberAuroraSafeBase baseObject = new CWE22_P12_V1_AmberAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberAuroraSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberAuroraSafeSink extends CWE22_P12_V1_AmberAuroraSafeBase {
    public void action(String data) {
        String amberAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File amberAuroraFile = new File(amberAuroraRoot + data);
            FileInputStream amberAuroraStream = null;
            InputStreamReader amberAuroraStreamReader = null;
            BufferedReader amberAuroraReader = null;
            if (amberAuroraFile.exists() && amberAuroraFile.isFile()) {
                try {
                    amberAuroraStream = new FileInputStream(amberAuroraFile);
                    amberAuroraStreamReader = new InputStreamReader(amberAuroraStream, "UTF-8");
                    amberAuroraReader = new BufferedReader(amberAuroraStreamReader);
                    System.out.println(amberAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberAuroraReader != null) {
                            amberAuroraReader.close();
                        }
                        if (amberAuroraStreamReader != null) {
                            amberAuroraStreamReader.close();
                        }
                        if (amberAuroraStream != null) {
                            amberAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
