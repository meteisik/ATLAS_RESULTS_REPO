import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_SaffronFlare {
    private static boolean privateReturnsTrue() { return true; }

    private String saffronFlareData;

    private void sinkSaffronFlare() throws XPathExpressionException {
        String data = saffronFlareData;
        String saffronFlareXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronFlareXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronFlareXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronFlareTokens = data.split("||");
            if (saffronFlareTokens.length < 2) {
                return;
            }
            String saffronFlareUser = saffronFlareTokens[0];
            String saffronFlarePass = saffronFlareTokens[1];
            XPath saffronFlareXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronFlareXml = new InputSource(saffronFlareXmlFile);
            String saffronFlareQuery = "//users/user[name/text()='" + saffronFlareUser
                    + "' and pass/text()='" + saffronFlarePass + "']" + "/secret/text()";
            String saffronFlareSecret = (String) saffronFlareXPath.evaluate(saffronFlareQuery, saffronFlareXml, XPathConstants.STRING);
            System.out.println(saffronFlareSecret);
        }
    }

    public void runSaffronFlare() throws XPathExpressionException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SAFFRON_FLARE_ADD");
        } else {
            data = null;
        }
        saffronFlareData = data;
        sinkSaffronFlare();
    }
}
