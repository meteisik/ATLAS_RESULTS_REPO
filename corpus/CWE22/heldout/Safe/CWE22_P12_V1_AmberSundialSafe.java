import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberSundialSafe {

    public void openAmberSundial() {
        String data;
        data = "foo";
        CWE22_P12_V1_AmberSundialSafeBase baseObject = new CWE22_P12_V1_AmberSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberSundialSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberSundialSafeSink extends CWE22_P12_V1_AmberSundialSafeBase {
    public void action(String data) {
        String amberSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File amberSundialFile = new File(amberSundialRoot + data);
            FileInputStream amberSundialStream = null;
            InputStreamReader amberSundialStreamReader = null;
            BufferedReader amberSundialReader = null;
            if (amberSundialFile.exists() && amberSundialFile.isFile()) {
                try {
                    amberSundialStream = new FileInputStream(amberSundialFile);
                    amberSundialStreamReader = new InputStreamReader(amberSundialStream, "UTF-8");
                    amberSundialReader = new BufferedReader(amberSundialStreamReader);
                    System.out.println(amberSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_AmberSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberSundialReader != null) {
                            amberSundialReader.close();
                        }
                        if (amberSundialStreamReader != null) {
                            amberSundialStreamReader.close();
                        }
                        if (amberSundialStream != null) {
                            amberSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_AmberSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
