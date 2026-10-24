import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_AmberSundial {

    public void openAmberSundial() {
        String data;
        data = System.getenv("AMBER_SUNDIAL_PATH");
        CWE22_P12_V1_AmberSundialBase baseObject = new CWE22_P12_V1_AmberSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_AmberSundialBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_AmberSundialSink extends CWE22_P12_V1_AmberSundialBase {
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
                    Logger.getLogger("CWE22_P12_V1_AmberSundialSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V1_AmberSundialSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
