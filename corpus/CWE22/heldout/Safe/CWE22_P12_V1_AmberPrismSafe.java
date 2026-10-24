import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberPrismSafe {

    public void openAmberPrism() {
        String data;
        data = "foo";
        CWE22_P12_V1_AmberPrismSafeBase baseObject = new CWE22_P12_V1_AmberPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberPrismSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberPrismSafeSink extends CWE22_P12_V1_AmberPrismSafeBase {
    public void action(String data) {
        String amberPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File amberPrismFile = new File(amberPrismRoot + data);
            FileInputStream amberPrismStream = null;
            InputStreamReader amberPrismStreamReader = null;
            BufferedReader amberPrismReader = null;
            if (amberPrismFile.exists() && amberPrismFile.isFile()) {
                try {
                    amberPrismStream = new FileInputStream(amberPrismFile);
                    amberPrismStreamReader = new InputStreamReader(amberPrismStream, "UTF-8");
                    amberPrismReader = new BufferedReader(amberPrismStreamReader);
                    System.out.println(amberPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberPrismReader != null) {
                            amberPrismReader.close();
                        }
                        if (amberPrismStreamReader != null) {
                            amberPrismStreamReader.close();
                        }
                        if (amberPrismStream != null) {
                            amberPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
