import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_AmberSundialSafe {
    public static String data;
    private static boolean privateReturnsTrue() { return true; }

    public void openAmberSundial() {
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_AmberSundialSafeSink()).readAmberSundial();
    }
}

class CWE22_P10_V2_AmberSundialSafeSink {
    public void readAmberSundial() {
        String data = CWE22_P10_V2_AmberSundialSafe.data;
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
                    Logger.getLogger("CWE22_P10_V2_AmberSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V2_AmberSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
