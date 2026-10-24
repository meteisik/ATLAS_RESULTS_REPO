import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SilentKestrel {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runSilentKestrel() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE643_P07_V2_SilentKestrelSource()).sourceSilentKestrel();
        } else {
            data = null;
        }
        String silentKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentKestrelTokens = data.split("||");
            if (silentKestrelTokens.length < 2) {
                return;
            }
            String silentKestrelUser = silentKestrelTokens[0];
            String silentKestrelPass = silentKestrelTokens[1];
            XPath silentKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource silentKestrelXml = new InputSource(silentKestrelXmlFile);
            String silentKestrelQuery = "//users/user[name/text()='" + silentKestrelUser
                    + "' and pass/text()='" + silentKestrelPass + "']" + "/secret/text()";
            String silentKestrelSecret = (String) silentKestrelXPath.evaluate(silentKestrelQuery, silentKestrelXml, XPathConstants.STRING);
            System.out.println(silentKestrelSecret);
        }
    }
}

class CWE643_P07_V2_SilentKestrelSource {

    public String sourceSilentKestrel() {
        String data;
        data = System.getenv("SILENT_KESTREL_ADD");
        return data;
    }
}
