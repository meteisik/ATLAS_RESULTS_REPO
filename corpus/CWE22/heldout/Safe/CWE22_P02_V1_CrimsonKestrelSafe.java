import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_CrimsonKestrelSafe {

    public void openCrimsonKestrel() {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String crimsonKestrelRoot = "/home/user/uploads/";
            if (data != null) {
                File crimsonKestrelFile = new File(crimsonKestrelRoot + data);
                FileInputStream crimsonKestrelStream = null;
                InputStreamReader crimsonKestrelStreamReader = null;
                BufferedReader crimsonKestrelReader = null;
                if (crimsonKestrelFile.exists() && crimsonKestrelFile.isFile()) {
                    try {
                        crimsonKestrelStream = new FileInputStream(crimsonKestrelFile);
                        crimsonKestrelStreamReader = new InputStreamReader(crimsonKestrelStream, "UTF-8");
                        crimsonKestrelReader = new BufferedReader(crimsonKestrelStreamReader);
                        System.out.println(crimsonKestrelReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V1_CrimsonKestrelSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (crimsonKestrelReader != null) {
                                crimsonKestrelReader.close();
                            }
                            if (crimsonKestrelStreamReader != null) {
                                crimsonKestrelStreamReader.close();
                            }
                            if (crimsonKestrelStream != null) {
                                crimsonKestrelStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V1_CrimsonKestrelSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
