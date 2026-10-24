import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_IvoryKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openIvoryKestrel() {
        String dataCopy;
        {
            String data;
            if (IO.STATIC_FINAL_TRUE) {
                data = System.getenv("IVORY_KESTREL_PATH");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V2_IvoryKestrel").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V2_IvoryKestrel").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
