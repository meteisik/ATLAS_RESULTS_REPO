import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_IvoryOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openIvoryOrbit() {
        String dataCopy;
        {
            String data;
            if (IO.staticFive == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String ivoryOrbitRoot = "/home/user/uploads/";
            if (data != null) {
                File ivoryOrbitFile = new File(ivoryOrbitRoot + data);
                FileInputStream ivoryOrbitStream = null;
                InputStreamReader ivoryOrbitStreamReader = null;
                BufferedReader ivoryOrbitReader = null;
                if (ivoryOrbitFile.exists() && ivoryOrbitFile.isFile()) {
                    try {
                        ivoryOrbitStream = new FileInputStream(ivoryOrbitFile);
                        ivoryOrbitStreamReader = new InputStreamReader(ivoryOrbitStream, "UTF-8");
                        ivoryOrbitReader = new BufferedReader(ivoryOrbitStreamReader);
                        System.out.println(ivoryOrbitReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V2_IvoryOrbitSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (ivoryOrbitReader != null) {
                                ivoryOrbitReader.close();
                            }
                            if (ivoryOrbitStreamReader != null) {
                                ivoryOrbitStreamReader.close();
                            }
                            if (ivoryOrbitStream != null) {
                                ivoryOrbitStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V2_IvoryOrbitSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
