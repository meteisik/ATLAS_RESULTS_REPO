import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_CobaltKestrel {

    public void openCobaltKestrel() {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_KESTREL_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String cobaltKestrelRoot = "/home/user/uploads/";
            if (data != null) {
                File cobaltKestrelFile = new File(cobaltKestrelRoot + data);
                FileInputStream cobaltKestrelStream = null;
                InputStreamReader cobaltKestrelStreamReader = null;
                BufferedReader cobaltKestrelReader = null;
                if (cobaltKestrelFile.exists() && cobaltKestrelFile.isFile()) {
                    try {
                        cobaltKestrelStream = new FileInputStream(cobaltKestrelFile);
                        cobaltKestrelStreamReader = new InputStreamReader(cobaltKestrelStream, "UTF-8");
                        cobaltKestrelReader = new BufferedReader(cobaltKestrelStreamReader);
                        System.out.println(cobaltKestrelReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V1_CobaltKestrel").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (cobaltKestrelReader != null) {
                                cobaltKestrelReader.close();
                            }
                            if (cobaltKestrelStreamReader != null) {
                                cobaltKestrelStreamReader.close();
                            }
                            if (cobaltKestrelStream != null) {
                                cobaltKestrelStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V1_CobaltKestrel").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
