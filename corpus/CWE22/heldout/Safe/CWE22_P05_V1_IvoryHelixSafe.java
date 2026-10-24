import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_IvoryHelixSafe {
    private String ivoryHelixData;

    private void readIvoryHelix() {
        String data = ivoryHelixData;
        String ivoryHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryHelixFile = new File(ivoryHelixRoot + data);
            FileInputStream ivoryHelixStream = null;
            InputStreamReader ivoryHelixStreamReader = null;
            BufferedReader ivoryHelixReader = null;
            if (ivoryHelixFile.exists() && ivoryHelixFile.isFile()) {
                try {
                    ivoryHelixStream = new FileInputStream(ivoryHelixFile);
                    ivoryHelixStreamReader = new InputStreamReader(ivoryHelixStream, "UTF-8");
                    ivoryHelixReader = new BufferedReader(ivoryHelixStreamReader);
                    System.out.println(ivoryHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_IvoryHelixSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryHelixReader != null) {
                            ivoryHelixReader.close();
                        }
                        if (ivoryHelixStreamReader != null) {
                            ivoryHelixStreamReader.close();
                        }
                        if (ivoryHelixStream != null) {
                            ivoryHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_IvoryHelixSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openIvoryHelix() {
        String data;
        data = "foo";
        ivoryHelixData = data;
        readIvoryHelix();
    }
}
