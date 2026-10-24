import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SaffronAuroraSafe {
    private static int privateFive = 5;

    public void runSaffronAurora() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P06_V2_SaffronAuroraSafeSink()).sinkSaffronAurora(data);
    }
}

class CWE643_P06_V2_SaffronAuroraSafeSink {

    public void sinkSaffronAurora(String data) throws XPathExpressionException {
        String saffronAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronAuroraTokens = data.split("||");
            if (saffronAuroraTokens.length < 2) {
                return;
            }
            String saffronAuroraUser = saffronAuroraTokens[0];
            String saffronAuroraPass = saffronAuroraTokens[1];
            XPath saffronAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronAuroraXml = new InputSource(saffronAuroraXmlFile);
            String saffronAuroraQuery = "//users/user[name/text()='" + saffronAuroraUser
                    + "' and pass/text()='" + saffronAuroraPass + "']" + "/secret/text()";
            String saffronAuroraSecret = (String) saffronAuroraXPath.evaluate(saffronAuroraQuery, saffronAuroraXml, XPathConstants.STRING);
            System.out.println(saffronAuroraSecret);
        }
    }
}
