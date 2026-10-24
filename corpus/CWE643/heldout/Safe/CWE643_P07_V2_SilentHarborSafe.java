import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SilentHarborSafe {
    private static boolean privateTrue = true;

    public void runSilentHarbor() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = (new CWE643_P07_V2_SilentHarborSafeSource()).sourceSilentHarbor();
        } else {
            data = null;
        }
        String silentHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            silentHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            silentHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] silentHarborTokens = data.split("||");
            if (silentHarborTokens.length < 2) {
                return;
            }
            String silentHarborUser = silentHarborTokens[0];
            String silentHarborPass = silentHarborTokens[1];
            XPath silentHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource silentHarborXml = new InputSource(silentHarborXmlFile);
            String silentHarborQuery = "//users/user[name/text()='" + silentHarborUser
                    + "' and pass/text()='" + silentHarborPass + "']" + "/secret/text()";
            String silentHarborSecret = (String) silentHarborXPath.evaluate(silentHarborQuery, silentHarborXml, XPathConstants.STRING);
            System.out.println(silentHarborSecret);
        }
    }
}

class CWE643_P07_V2_SilentHarborSafeSource {

    public String sourceSilentHarbor() {
        String data;
        data = "foo";
        return data;
    }
}
