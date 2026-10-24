import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SilentLanternSafe {
    private static boolean privateTrue = true;

    public void runSilentLantern() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_SilentLanternSafeSink()).sinkSilentLantern(data);
    }
}

class CWE643_P06_V2_SilentLanternSafeSink {

    public void sinkSilentLantern(String data) throws XPathExpressionException {
        String silentLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentLanternTokens = data.split("||");
            if (silentLanternTokens.length < 2) {
                return;
            }
            String silentLanternUser = silentLanternTokens[0];
            String silentLanternPass = silentLanternTokens[1];
            XPath silentLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource silentLanternXml = new InputSource(silentLanternXmlFile);
            String silentLanternQuery = "//users/user[name/text()='" + silentLanternUser
                    + "' and pass/text()='" + silentLanternPass + "']" + "/secret/text()";
            String silentLanternSecret = (String) silentLanternXPath.evaluate(silentLanternQuery, silentLanternXml, XPathConstants.STRING);
            System.out.println(silentLanternSecret);
        }
    }
}
