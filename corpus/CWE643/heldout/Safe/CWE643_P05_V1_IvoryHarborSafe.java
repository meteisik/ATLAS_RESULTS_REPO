import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_IvoryHarborSafe {

    private String ivoryHarborData;

    private void sinkIvoryHarbor() throws XPathExpressionException {
        String data = ivoryHarborData;
        String ivoryHarborXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryHarborXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryHarborXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryHarborTokens = data.split("||");
            if (ivoryHarborTokens.length < 2) {
                return;
            }
            String ivoryHarborUser = ivoryHarborTokens[0];
            String ivoryHarborPass = ivoryHarborTokens[1];
            XPath ivoryHarborXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryHarborXml = new InputSource(ivoryHarborXmlFile);
            String ivoryHarborQuery = "//users/user[name/text()='" + ivoryHarborUser
                    + "' and pass/text()='" + ivoryHarborPass + "']" + "/secret/text()";
            String ivoryHarborSecret = (String) ivoryHarborXPath.evaluate(ivoryHarborQuery, ivoryHarborXml, XPathConstants.STRING);
            System.out.println(ivoryHarborSecret);
        }
    }

    public void runIvoryHarbor() throws XPathExpressionException {
        String data;
        data = "foo";
        ivoryHarborData = data;
        sinkIvoryHarbor();
    }
}
