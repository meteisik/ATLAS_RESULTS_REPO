import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_IvoryLotusSafe {

    private void sinkIvoryLotus(String data) throws XPathExpressionException {
        String ivoryLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryLotusTokens = data.split("||");
            if (ivoryLotusTokens.length < 2) {
                return;
            }
            String ivoryLotusUser = ivoryLotusTokens[0];
            String ivoryLotusPass = ivoryLotusTokens[1];
            XPath ivoryLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryLotusXml = new InputSource(ivoryLotusXmlFile);
            String ivoryLotusQuery = "//users/user[name/text()='" + ivoryLotusUser
                    + "' and pass/text()='" + ivoryLotusPass + "']" + "/secret/text()";
            String ivoryLotusSecret = (String) ivoryLotusXPath.evaluate(ivoryLotusQuery, ivoryLotusXml, XPathConstants.STRING);
            System.out.println(ivoryLotusSecret);
        }
    }

    public void runIvoryLotus() throws XPathExpressionException {
        String data;
        data = "foo";
        sinkIvoryLotus(data);
    }
}
