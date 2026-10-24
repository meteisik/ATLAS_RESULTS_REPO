import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_NovaAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String locateNovaAurora() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void openNovaAurora() {
        String data = locateNovaAurora();
        String novaAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File novaAuroraFile = new File(novaAuroraRoot + data);
            FileInputStream novaAuroraStream = null;
            InputStreamReader novaAuroraStreamReader = null;
            BufferedReader novaAuroraReader = null;
            if (novaAuroraFile.exists() && novaAuroraFile.isFile()) {
                try {
                    novaAuroraStream = new FileInputStream(novaAuroraFile);
                    novaAuroraStreamReader = new InputStreamReader(novaAuroraStream, "UTF-8");
                    novaAuroraReader = new BufferedReader(novaAuroraStreamReader);
                    System.out.println(novaAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V2_NovaAuroraSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaAuroraReader != null) {
                            novaAuroraReader.close();
                        }
                        if (novaAuroraStreamReader != null) {
                            novaAuroraStreamReader.close();
                        }
                        if (novaAuroraStream != null) {
                            novaAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V2_NovaAuroraSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
