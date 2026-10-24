import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_IvoryKestrel {

    private String locateIvoryKestrel() {
        String data;
        data = System.getenv("IVORY_KESTREL_PATH");
        return data;
    }

    public void openIvoryKestrel() {
        String data = locateIvoryKestrel();
        String ivoryKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryKestrelFile = new File(ivoryKestrelRoot + data);
            FileInputStream ivoryKestrelStream = null;
            InputStreamReader ivoryKestrelStreamReader = null;
            BufferedReader ivoryKestrelReader = null;
            if (ivoryKestrelFile.exists() && ivoryKestrelFile.isFile()) {
                try {
                    ivoryKestrelStream = new FileInputStream(ivoryKestrelFile);
                    ivoryKestrelStreamReader = new InputStreamReader(ivoryKestrelStream, "UTF-8");
                    ivoryKestrelReader = new BufferedReader(ivoryKestrelStreamReader);
                    System.out.println(ivoryKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_IvoryKestrel").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryKestrelReader != null) {
                            ivoryKestrelReader.close();
                        }
                        if (ivoryKestrelStreamReader != null) {
                            ivoryKestrelStreamReader.close();
                        }
                        if (ivoryKestrelStream != null) {
                            ivoryKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_IvoryKestrel").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
