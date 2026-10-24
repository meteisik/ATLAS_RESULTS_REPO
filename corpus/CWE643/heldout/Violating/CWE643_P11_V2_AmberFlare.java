import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberFlare {
    private static boolean privateTrue = true;

    public void runAmberFlare() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = System.getenv("AMBER_FLARE_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberFlareSink()).sinkAmberFlare(dataHashMap);
    }
}

class CWE643_P11_V2_AmberFlareSink {

    public void sinkAmberFlare(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberFlareTokens = data.split("||");
            if (amberFlareTokens.length < 2) {
                return;
            }
            String amberFlareUser = amberFlareTokens[0];
            String amberFlarePass = amberFlareTokens[1];
            XPath amberFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource amberFlareXml = new InputSource(amberFlareXmlFile);
            String amberFlareQuery = "//users/user[name/text()='" + amberFlareUser
                    + "' and pass/text()='" + amberFlarePass + "']" + "/secret/text()";
            String amberFlareSecret = (String) amberFlareXPath.evaluate(amberFlareQuery, amberFlareXml, XPathConstants.STRING);
            System.out.println(amberFlareSecret);
        }
    }
}
