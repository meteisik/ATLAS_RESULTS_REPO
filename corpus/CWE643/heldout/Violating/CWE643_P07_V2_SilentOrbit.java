import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SilentOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSilentOrbit() throws XPathExpressionException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = (new CWE643_P07_V2_SilentOrbitSource()).sourceSilentOrbit();
        } else {
            data = null;
        }
        String silentOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentOrbitTokens = data.split("||");
            if (silentOrbitTokens.length < 2) {
                return;
            }
            String silentOrbitUser = silentOrbitTokens[0];
            String silentOrbitPass = silentOrbitTokens[1];
            XPath silentOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource silentOrbitXml = new InputSource(silentOrbitXmlFile);
            String silentOrbitQuery = "//users/user[name/text()='" + silentOrbitUser
                    + "' and pass/text()='" + silentOrbitPass + "']" + "/secret/text()";
            String silentOrbitSecret = (String) silentOrbitXPath.evaluate(silentOrbitQuery, silentOrbitXml, XPathConstants.STRING);
            System.out.println(silentOrbitSecret);
        }
    }
}

class CWE643_P07_V2_SilentOrbitSource {

    public String sourceSilentOrbit() {
        String data;
        data = System.getenv("SILENT_ORBIT_ADD");
        return data;
    }
}
